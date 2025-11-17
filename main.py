import os
from datetime import datetime, timedelta, timezone
from typing import Optional, List, Literal

from fastapi import FastAPI, HTTPException, Depends, Header
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr
from bson import ObjectId

from database import db, create_document, get_documents
from schemas import User as UserSchema, Service as ServiceSchema, Booking as BookingSchema, Payment as PaymentSchema, Review as ReviewSchema

import jwt
from passlib.context import CryptContext
import stripe

# Environment
JWT_SECRET = os.getenv("JWT_SECRET", "dev-secret")
JWT_EXPIRES_MIN = int(os.getenv("JWT_EXPIRES_MIN", "60"))
STRIPE_SECRET_KEY = os.getenv("STRIPE_SECRET_KEY", "sk_test_123")
stripe.api_key = STRIPE_SECRET_KEY

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
security = HTTPBearer()

# Helpers

def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)

def create_token(user: dict) -> str:
    payload = {
        "sub": str(user["_id"]),
        "role": user.get("role", "customer"),
        "exp": datetime.now(timezone.utc) + timedelta(minutes=JWT_EXPIRES_MIN),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm="HS256")

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    try:
        token = credentials.credentials
        payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        user_id = payload.get("sub")
        user = db["user"].find_one({"_id": ObjectId(user_id)})
        if not user:
            raise HTTPException(status_code=401, detail="Invalid user")
        return user
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid token")

class RoleGuard:
    def __init__(self, roles: List[str]):
        self.roles = roles
    def __call__(self, user=Depends(get_current_user)):
        if user.get("role") not in self.roles:
            raise HTTPException(status_code=403, detail="Forbidden")
        return user

# Models
class SignupBody(BaseModel):
    name: Optional[str] = None
    email: EmailStr
    password: str
    role: Literal["customer", "cleaner", "admin"] = "customer"

class LoginBody(BaseModel):
    email: EmailStr
    password: str

class ProfileUpdateBody(BaseModel):
    name: Optional[str] = None
    phone: Optional[str] = None
    addressStreet: Optional[str] = None
    addressCity: Optional[str] = None
    addressState: Optional[str] = None
    addressZip: Optional[str] = None
    bio: Optional[str] = None
    serviceArea: Optional[str] = None
    rateType: Optional[Literal["hourly", "flat"]] = None
    rateAmount: Optional[float] = None

class BookingCreateBody(BaseModel):
    serviceId: str
    dateTime: datetime
    addressStreet: str
    addressCity: str
    addressState: str
    addressZip: str
    homeSize: str

class StatusUpdateBody(BaseModel):
    status: Literal["Assigned", "Scheduled", "OnTheWay", "InProgress", "Completed", "Cancelled"]
    cleanerId: Optional[str] = None

class ReviewBody(BaseModel):
    rating: int
    comment: Optional[str] = None

class PricingConfig(BaseModel):
    base: dict

# Seed default services if empty
@app.on_event("startup")
def seed_services():
    if db is None:
        return
    if db["service"].count_documents({}) == 0:
        services = [
            {"name": "Standard Cleaning", "description": "Routine clean", "basePrice": 8000, "pricingType": "flat", "active": True},
            {"name": "Deep Cleaning", "description": "Thorough clean", "basePrice": 15000, "pricingType": "flat", "active": True},
            {"name": "Move-Out Cleaning", "description": "Move related", "basePrice": 20000, "pricingType": "flat", "active": True},
            {"name": "Custom", "description": "Custom quote", "basePrice": 10000, "pricingType": "flat", "active": True},
        ]
        for s in services:
            db["service"].insert_one({**s, "created_at": datetime.now(timezone.utc), "updated_at": datetime.now(timezone.utc)})

@app.get("/")
def root():
    return {"message": "Cleaning Service API running"}

@app.get("/test")
def test_database():
    response = {
        "backend": "✅ Running",
        "database": "❌ Not Available",
        "database_url": "✅ Set" if os.getenv("DATABASE_URL") else "❌ Not Set",
        "database_name": "✅ Set" if os.getenv("DATABASE_NAME") else "❌ Not Set",
        "connection_status": "Not Connected",
        "collections": []
    }
    try:
        if db is not None:
            response["database"] = "✅ Available"
            response["connection_status"] = "Connected"
            response["collections"] = db.list_collection_names()
    except Exception as e:
        response["database"] = f"Error: {str(e)}"
    return response

# Auth
@app.post("/api/auth/signup")
def signup(body: SignupBody):
    if db["user"].find_one({"email": body.email}):
        raise HTTPException(status_code=400, detail="Email already registered")
    user_doc = {
        "name": body.name,
        "email": body.email,
        "hashedPassword": hash_password(body.password),
        "role": body.role,
        "created_at": datetime.now(timezone.utc),
        "updated_at": datetime.now(timezone.utc),
    }
    db["user"].insert_one(user_doc)
    token = create_token(user_doc | {"_id": user_doc.get("_id", None)})
    # fetch inserted user to get _id
    u = db["user"].find_one({"email": body.email})
    token = create_token(u)
    return {"token": token}

@app.post("/api/auth/login")
def login(body: LoginBody):
    user = db["user"].find_one({"email": body.email})
    if not user or not verify_password(body.password, user.get("hashedPassword", "")):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    token = create_token(user)
    return {"token": token}

# Me
@app.get("/api/me")
def me(user=Depends(get_current_user)):
    user["_id"] = str(user["_id"])
    return user

@app.put("/api/me")
def update_me(body: ProfileUpdateBody, user=Depends(get_current_user)):
    updates = {k: v for k, v in body.model_dump().items() if v is not None}
    updates["updated_at"] = datetime.now(timezone.utc)
    db["user"].update_one({"_id": user["_id"]}, {"$set": updates})
    u = db["user"].find_one({"_id": user["_id"]})
    u["_id"] = str(u["_id"])
    return u

# Services
@app.get("/api/services")
def list_services():
    items = list(db["service"].find({"active": True}))
    for x in items:
        x["_id"] = str(x["_id"])
    return items

# Pricing helper
HOME_SIZE_MULTIPLIER = {
    "studio": 1.0,
    "1 bed / 1 bath": 1.0,
    "2 bed / 1 bath": 1.2,
    "2 bed / 2 bath": 1.35,
    "3 bed / 2 bath": 1.6,
    "4+ bed": 2.0,
}

def estimate_price(service: dict, home_size: str) -> int:
    base = service.get("basePrice", 10000)
    mult = HOME_SIZE_MULTIPLIER.get(home_size, 1.0)
    return int(base * mult)

# Bookings
@app.post("/api/bookings")
def create_booking(body: BookingCreateBody, user=Depends(RoleGuard(["customer"]))):
    service = db["service"].find_one({"_id": ObjectId(body.serviceId)})
    if not service:
        raise HTTPException(status_code=400, detail="Invalid service")
    est = estimate_price(service, body.homeSize)
    booking = {
        "customerId": str(user["_id"]),
        "cleanerId": None,
        "serviceId": body.serviceId,
        "dateTime": body.dateTime,
        "addressStreet": body.addressStreet,
        "addressCity": body.addressCity,
        "addressState": body.addressState,
        "addressZip": body.addressZip,
        "homeSize": body.homeSize,
        "status": "Requested",
        "estimatedPrice": est,
        "finalPrice": None,
        "paymentStatus": "Pending",
        "created_at": datetime.now(timezone.utc),
        "updated_at": datetime.now(timezone.utc),
    }
    res = db["booking"].insert_one(booking)
    booking["_id"] = str(res.inserted_id)
    return booking

@app.get("/api/bookings")
def list_bookings(user=Depends(get_current_user)):
    role = user.get("role")
    q = {}
    if role == "customer":
        q["customerId"] = str(user["_id"]) 
    elif role == "cleaner":
        q["$or"] = [{"cleanerId": str(user["_id"])}, {"cleanerId": None, "status": "Requested"}]
    items = list(db["booking"].find(q))
    for x in items:
        x["_id"] = str(x["_id"])  
    return items

@app.get("/api/bookings/{booking_id}")
def get_booking(booking_id: str, user=Depends(get_current_user)):
    b = db["booking"].find_one({"_id": ObjectId(booking_id)})
    if not b:
        raise HTTPException(status_code=404, detail="Not found")
    if user.get("role") == "customer" and b.get("customerId") != str(user["_id"]):
        raise HTTPException(status_code=403, detail="Forbidden")
    if user.get("role") == "cleaner" and b.get("cleanerId") not in (None, str(user["_id"])):
        raise HTTPException(status_code=403, detail="Forbidden")
    b["_id"] = str(b["_id"]) 
    return b

@app.put("/api/bookings/{booking_id}/status")
def update_status(booking_id: str, body: StatusUpdateBody, user=Depends(get_current_user)):
    b = db["booking"].find_one({"_id": ObjectId(booking_id)})
    if not b:
        raise HTTPException(status_code=404, detail="Not found")
    role = user.get("role")

    # Assignment logic
    if body.status in ["Assigned", "Scheduled"]:
        if role not in ("cleaner", "admin"):
            raise HTTPException(status_code=403, detail="Only cleaner/admin can assign/schedule")
        if b.get("cleanerId") and str(b.get("cleanerId")) != str(user["_id"]) and role != "admin":
            raise HTTPException(status_code=403, detail="Not your job")
        cleaner_id = body.cleanerId or str(user["_id"]) if role == "cleaner" else body.cleanerId
        if not cleaner_id:
            raise HTTPException(status_code=400, detail="cleanerId required")
        updates = {"status": body.status, "cleanerId": cleaner_id}
    else:
        # Other transitions
        if role == "cleaner":
            if b.get("cleanerId") not in (None, str(user["_id"])):
                raise HTTPException(status_code=403, detail="Not your job")
        elif role == "customer":
            if b.get("customerId") != str(user["_id"]):
                raise HTTPException(status_code=403, detail="Forbidden")
        updates = {"status": body.status}

    updates["updated_at"] = datetime.now(timezone.utc)
    db["booking"].update_one({"_id": b["_id"]}, {"$set": updates})

    # If completed, trigger charge
    if body.status == "Completed":
        try:
            charge_booking(booking_id, user)
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Completion charge failed: {str(e)}")

    b = db["booking"].find_one({"_id": ObjectId(booking_id)})
    b["_id"] = str(b["_id"]) 
    return b

# Payments
class SetupBody(BaseModel):
    paymentMethodId: Optional[str] = None

@app.post("/api/payments/setup")
def setup_payment_method(body: SetupBody, user=Depends(RoleGuard(["customer"]))):
    # Ensure Stripe customer
    if not user.get("stripeCustomerId"):
        customer = stripe.Customer.create(email=user.get("email"), name=user.get("name"))
        db["user"].update_one({"_id": user["_id"]}, {"$set": {"stripeCustomerId": customer.id}})
        user["stripeCustomerId"] = customer.id

    if body.paymentMethodId:
        stripe.PaymentMethod.attach(body.paymentMethodId, customer=user["stripeCustomerId"]) 
        stripe.Customer.modify(user["stripeCustomerId"], invoice_settings={"default_payment_method": body.paymentMethodId})
        db["user"].update_one({"_id": user["_id"]}, {"$set": {"defaultPaymentMethodId": body.paymentMethodId}})
        return {"status": "attached"}

    setup_intent = stripe.SetupIntent.create(customer=user["stripeCustomerId"], payment_method_types=["card"])
    return {"clientSecret": setup_intent.client_secret}

@app.post("/api/bookings/{booking_id}/charge")
def charge_booking(booking_id: str, user=Depends(RoleGuard(["admin", "cleaner"]))):
    b = db["booking"].find_one({"_id": ObjectId(booking_id)})
    if not b:
        raise HTTPException(status_code=404, detail="Not found")
    customer = db["user"].find_one({"_id": ObjectId(b["customerId"])})
    if not customer or not customer.get("stripeCustomerId"):
        raise HTTPException(status_code=400, detail="Customer missing Stripe setup")

    amount = b.get("finalPrice") or b.get("estimatedPrice")
    pm = customer.get("defaultPaymentMethodId")
    if not pm:
        raise HTTPException(status_code=400, detail="No payment method on file")

    intent = stripe.PaymentIntent.create(
        amount=amount,
        currency="usd",
        customer=customer["stripeCustomerId"],
        payment_method=pm,
        off_session=True,
        confirm=True,
        description=f"Cleaning booking {booking_id}",
    )

    pay_doc = {
        "bookingId": booking_id,
        "amount": amount,
        "currency": "usd",
        "stripePaymentIntentId": intent.id,
        "status": intent.status,
        "created_at": datetime.now(timezone.utc),
        "updated_at": datetime.now(timezone.utc),
    }
    db["payment"].insert_one(pay_doc)

    db["booking"].update_one({"_id": ObjectId(booking_id)}, {"$set": {"paymentStatus": "Paid", "finalPrice": amount, "updated_at": datetime.now(timezone.utc)}})

    return {"status": intent.status, "paymentIntentId": intent.id}

@app.post("/api/payments/{payment_id}/refund")
def refund(payment_id: str, user=Depends(RoleGuard(["admin"]))):
    pay = db["payment"].find_one({"_id": ObjectId(payment_id)})
    if not pay:
        raise HTTPException(status_code=404, detail="Payment not found")
    intent_id = pay.get("stripePaymentIntentId")
    if not intent_id:
        raise HTTPException(status_code=400, detail="Missing PaymentIntent")

    r = stripe.Refund.create(payment_intent=intent_id)

    db["payment"].update_one({"_id": pay["_id"]}, {"$set": {"status": "refunded", "updated_at": datetime.now(timezone.utc)}})

    b = db["booking"].find_one({"_id": ObjectId(pay["bookingId"])})
    if b:
        db["booking"].update_one({"_id": b["_id"]}, {"$set": {"paymentStatus": "Refunded", "updated_at": datetime.now(timezone.utc)}})

    return {"status": "refunded", "refundId": r.id}

# Reviews
@app.post("/api/bookings/{booking_id}/review")
def create_review(booking_id: str, body: ReviewBody, user=Depends(RoleGuard(["customer"]))):
    b = db["booking"].find_one({"_id": ObjectId(booking_id)})
    if not b or b.get("customerId") != str(user["_id"]):
        raise HTTPException(status_code=403, detail="Forbidden")
    if b.get("status") != "Completed":
        raise HTTPException(status_code=400, detail="Can review only completed jobs")
    review = {
        "bookingId": booking_id,
        "customerId": str(user["_id"]),
        "cleanerId": b.get("cleanerId"),
        "rating": body.rating,
        "comment": body.comment,
        "created_at": datetime.now(timezone.utc),
        "updated_at": datetime.now(timezone.utc),
    }
    db["review"].insert_one(review)
    return {"status": "ok"}

# Admin views
@app.get("/api/admin/users")
def admin_users(user=Depends(RoleGuard(["admin"]))):
    items = list(db["user"].find({}))
    for x in items:
        x["_id"] = str(x["_id"]) 
    return items

@app.get("/api/admin/bookings")
def admin_bookings(user=Depends(RoleGuard(["admin"]))):
    items = list(db["booking"].find({}))
    for x in items:
        x["_id"] = str(x["_id"]) 
    return items

@app.get("/api/admin/payments")
def admin_payments(user=Depends(RoleGuard(["admin"]))):
    items = list(db["payment"].find({}))
    for x in items:
        x["_id"] = str(x["_id"]) 
    return items

@app.get("/api/admin/analytics")
def admin_analytics(user=Depends(RoleGuard(["admin"]))):
    total = db["booking"].count_documents({})
    completed = db["booking"].count_documents({"status": "Completed"})
    payments = list(db["payment"].find({"status": "succeeded"}))
    revenue = sum(p.get("amount", 0) for p in payments)
    return {"totalBookings": total, "completedBookings": completed, "revenue": revenue}
