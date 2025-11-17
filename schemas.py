"""
Database Schemas for Cleaning Service Booking App

Each Pydantic model represents a MongoDB collection. Collection name is the lowercase of the class name.

Collections:
- user
- service
- booking
- payment
- review
"""

from pydantic import BaseModel, Field
from typing import Optional, Literal
from datetime import datetime

Role = Literal["customer", "cleaner", "admin"]

class User(BaseModel):
    name: Optional[str] = Field(None, description="Full name")
    email: str = Field(..., description="Email address")
    hashedPassword: Optional[str] = Field(None, description="BCrypt hash")
    phone: Optional[str] = Field(None)
    role: Role = Field("customer")
    # Address fields
    addressStreet: Optional[str] = None
    addressCity: Optional[str] = None
    addressState: Optional[str] = None
    addressZip: Optional[str] = None
    # Cleaner profile
    bio: Optional[str] = None
    serviceArea: Optional[str] = None
    rateType: Optional[Literal["hourly", "flat"]] = None
    rateAmount: Optional[float] = None
    # Stripe
    stripeCustomerId: Optional[str] = None
    defaultPaymentMethodId: Optional[str] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

class Service(BaseModel):
    name: str
    description: Optional[str] = None
    basePrice: float
    pricingType: Literal["hourly", "flat"] = "flat"
    active: bool = True
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

class Booking(BaseModel):
    customerId: str
    cleanerId: Optional[str] = None
    serviceId: str
    dateTime: datetime
    addressStreet: str
    addressCity: str
    addressState: str
    addressZip: str
    homeSize: str
    status: Literal[
        "Requested",
        "Assigned",
        "Scheduled",
        "OnTheWay",
        "InProgress",
        "Completed",
        "Cancelled"
    ] = "Requested"
    estimatedPrice: float
    finalPrice: Optional[float] = None
    paymentStatus: Literal["Pending", "Paid", "Refunded"] = "Pending"
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

class Payment(BaseModel):
    bookingId: str
    amount: int
    currency: str = "usd"
    stripePaymentIntentId: Optional[str] = None
    status: Literal["requires_payment_method", "requires_confirmation", "processing", "succeeded", "refunded", "failed"] = "processing"
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

class Review(BaseModel):
    bookingId: str
    customerId: str
    cleanerId: str
    rating: int = Field(..., ge=1, le=5)
    comment: Optional[str] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
