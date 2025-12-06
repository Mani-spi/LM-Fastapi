import json
import os
from datetime import datetime, timedelta
import uvicorn
from fastapi import FastAPI, Depends, Header, HTTPException
from sqlalchemy.orm import Session
from database import SessionLocal, engine
from models import (
    Customer, CustomerUserModel,
    Management, ManagementUserModel,
    MachineModel, SerialNumbers, LicenseData, Base,
    CustomerPrivilegeEnum, SerialHistory, ManagementPrivilegeEnum, ControllerModules, SoftwareKey
)
from auth import verify_api_key
from pydantic import BaseModel, Field
from typing import List, Optional
# from Cryptodome.Util.Padding import unpad
# from Cryptodome.PublicKey import RSA
# from Cryptodome.Cipher import PKCS1_OAEP, AES
# from Cryptodome.Random import get_random_bytes

from Crypto.Util.Padding import unpad
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives import hashes, serialization
import base64
import secrets
import string

app = FastAPI(title="Full CRUD API")


# ----------------- Initialize Database -----------------
@app.on_event("startup")
async def on_startup():
    # Create DB tables (sync call, safe in async fn)
    Base.metadata.create_all(bind=engine)


# ----------------- DB Dependency -----------------
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@app.get("/serials/max/{model_id}", dependencies=[Depends(verify_api_key)])
def get_max_serial(model_id: int, db: Session = Depends(get_db)):
    result = (
        db.query(SerialNumbers.serial_number)
        .filter(SerialNumbers.model_number == model_id)
        .all()
    )

    if not result:
        return {"max_number": 0}

    max_num = 0
    for row in result:
        # Extract numeric part from example "SPI 52"
        s = row.serial_number
        num = ''.join(filter(str.isdigit, s))
        if num.isdigit():
            max_num = max(max_num, int(num))

    return {"max_number": max_num}


def generate_16char_key():
    charset = string.ascii_letters + string.digits + string.punctuation
    return ''.join(secrets.choice(charset) for _ in range(16))


def generate_rsa_key_pair() -> dict:
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    ).decode()

    public_key = private_key.public_key()
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()

    return {
        "private_key": private_pem,
        "public_key": public_pem
    }


@app.get("/management_privileges/", response_model=list[dict[str, str]])
async def get_management_privileges() -> list[dict[str, str]]:
    return [
        {"value": priv.name, "label": priv.value}
        for priv in ManagementPrivilegeEnum
    ]


@app.get("/privileges/", response_model=list[dict[str, str]])
async def get_privileges() -> list[dict[str, str]]:
    return [
        {"value": priv.name, "label": priv.value}
        for priv in CustomerPrivilegeEnum
    ]


# ----------------- Pydantic Schemas -----------------
# Customers
class CustomerCreate(BaseModel):
    name: str
    phone: Optional[str]
    email: Optional[str]
    gst: Optional[str]
    latitude: str
    longitude: str
    address: str
    # private_key: str
    # public_key: str
    key_name: str

    class Config:
        orm_mode = True


class CustomerUpdate(BaseModel):
    name: Optional[str]
    phone: Optional[str]
    email: Optional[str]
    gst: Optional[str]
    latitude: str
    longitude: str
    address: str
    private_key: str
    public_key: str
    key_name: str


# Customer Users
class CustomerUserCreate(BaseModel):
    name: str
    username: str
    password: str
    designation: str
    privilege: str
    customer_id: int

    class Config:
        orm_mode = True


class CustomerUserUpdate(BaseModel):
    name: Optional[str]
    username: Optional[str]
    password: Optional[str]
    designation: Optional[str]
    privilege: Optional[str]


# Management
class ManagementCreate(BaseModel):
    name: str
    phone: Optional[str]
    email: Optional[str]
    gst: Optional[str]
    latitude: str
    longitude: str
    address: str
    # private_key: str
    # public_key: str
    key_name: str

    class Config:
        orm_mode = True


class ManagementUpdate(BaseModel):
    name: Optional[str]
    phone: Optional[str]
    email: Optional[str]
    gst: Optional[str]
    latitude: str
    longitude: str
    address: str
    private_key: str
    public_key: str
    key_name: str


# Management Users
class ManagementUserCreate(BaseModel):
    name: str
    username: str
    password: str
    designation: str
    privilege: str
    management_id: int

    class Config:
        orm_mode = True


class ManagementUserUpdate(BaseModel):
    name: Optional[str]
    username: Optional[str]
    password: Optional[str]
    designation: Optional[str]
    privilege: Optional[str]


# Machines
class MachineCreate(BaseModel):
    machineName: str
    model_number: str
    description: str
    default_warranty_months: int
    phase: str
    volts: str
    amps: str
    frequency: str
    prefix: str
    make: int

    class Config:
        orm_mode = True


class MachineUpdate(BaseModel):
    machineName: Optional[str]
    model_number: Optional[str]  # Added
    description: Optional[str]
    default_warranty_months: Optional[int]
    phase: Optional[str]
    volts: Optional[str]
    amps: Optional[str]
    frequency: Optional[str]
    prefix: Optional[str]
    make: Optional[int]  # Added

    class Config:
        orm_mode = True


# Serial Numbers
class SerialCreate(BaseModel):
    serial_number: str
    date_of_manufacturing: str
    additional_warranty_months: int
    warranty_end_date: str
    product_warranty: str
    model_number: int
    customer_id: int

    class Config:
        orm_mode = True


class SerialUpdate(BaseModel):
    additional_warranty_months: Optional[int]
    warranty_end_date: Optional[str]
    model_number: int
    customer_id: int


class SoftwareKeyCreate(BaseModel):
    sw_version: str
    pcb_version: str
    fw_version: str
    design_version: str
    license_type: str
    initial_date: str
    last_updated: str
    parameter: str
    software_key: str
    reason: str
    serial_number: int

    class Config:
        orm_mode = True


class SoftwareKeyUpdate(BaseModel):
    sw_version: Optional[str]
    pcb_version: Optional[str]
    fw_version: Optional[str]
    design_version: Optional[str]
    license_type: Optional[str]
    initial_date: Optional[str]
    last_updated: Optional[str]
    parameter: Optional[str]
    software_key: Optional[str]
    reason: Optional[str]
    serial_number: int


# License
class LicenseCreate(BaseModel):
    customer_id: int
    mother_board_serial: str
    enabled_machines: List[str] = Field(..., example=["HMI Network", "Flow Dispenser", "ChemChef Dispenser", "Dye Dispenser"])
    hmi_model_no: str
    hmi_serial_no: str
    flowi_model_no: str
    flowi_serial_no: str
    chem_chef_model_no: str
    chem_chef_serial_no: str
    dye_model_no: str
    dye_serial_no: str
    client_public_key: str

    class Config:
        orm_mode = True


class LicenseUpdate(BaseModel):
    customer_id: Optional[str] = None
    mother_board_serial: Optional[str] = None
    enabled_machines: Optional[str] = None
    client_public_key: Optional[str] = None


# Pydantic model for incoming encrypted payload
class EncryptedLicensePayload(BaseModel):
    encrypted_data: str  # Base64 encoded encrypted JSON string


# Encrypted payload model
class EncryptedLicenseCreate(BaseModel):
    encrypted_data: str  # Base64 encoded encrypted JSON string
    encrypted_key: str
    iv: str


# ----------------- Root -----------------
@app.get("/")
def read_root():
    return {"message": "Server is running!"}


# ----------------- CRUD Routes -----------------
# ----------------- Customers -----------------
@app.post("/customers", dependencies=[Depends(verify_api_key)])
def create_customer(customer: CustomerCreate, db: Session = Depends(get_db)):
    keys = generate_rsa_key_pair()
    db_customer = Customer(
        **customer.dict(),
        private_key=keys["private_key"],
        public_key=keys["public_key"]
    )
    db.add(db_customer)
    db.commit()
    db.refresh(db_customer)
    return db_customer


@app.get("/customers", dependencies=[Depends(verify_api_key)])
def list_customers(db: Session = Depends(get_db)):
    return db.query(Customer).all()


@app.get("/fetch_customer_public_key/{customer_id}", dependencies=[Depends(verify_api_key)])
def get_customer_public_key(customer_id=int, db: Session = Depends(get_db)):
    customer = db.query(Customer).filter(Customer.id == customer_id).first()
    if not customer:
        raise HTTPException(status_code=404, detail="Customer Not Found")

    if not customer.public_key:
        raise HTTPException(status_code=400, detail="Customer Public Key Not Found")

    return {'customer_id': customer.id, 'public_key': customer.public_key}


@app.put("/customers/{customer_id}", dependencies=[Depends(verify_api_key)])
def update_customer(customer_id: int, customer: CustomerUpdate, db: Session = Depends(get_db)):
    db_customer = db.query(Customer).get(customer_id)
    if not db_customer:
        raise HTTPException(status_code=404, detail="Customer not found")
    for key, value in customer.dict(exclude_unset=True).items():
        setattr(db_customer, key, value)
    db.commit()
    db.refresh(db_customer)
    return db_customer


@app.delete("/customers/{customer_id}", dependencies=[Depends(verify_api_key)])
def delete_customer(customer_id: int, db: Session = Depends(get_db)):
    db_customer = db.query(Customer).get(customer_id)
    if not db_customer:
        raise HTTPException(status_code=404, detail="Customer not found")
    db.delete(db_customer)
    db.commit()
    return {"message": "Customer deleted"}


# ----------------- Customer Users -----------------
@app.post("/customer-users", dependencies=[Depends(verify_api_key)])
def create_customer_user(user: CustomerUserCreate, db: Session = Depends(get_db)):
    db_user = CustomerUserModel(**user.dict())
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user


@app.get("/customer-users", dependencies=[Depends(verify_api_key)])
def list_customer_users(customer_id: int = None, db: Session = Depends(get_db)):
    query = db.query(CustomerUserModel)
    if customer_id is not None:
        query = query.filter(CustomerUserModel.customer_id == customer_id)
    return query.all()


@app.put("/customer-users/{user_id}", dependencies=[Depends(verify_api_key)])
def update_customer_user(user_id: int, user: CustomerUserUpdate, db: Session = Depends(get_db)):
    db_user = db.query(CustomerUserModel).get(user_id)
    if not db_user:
        raise HTTPException(status_code=404, detail="Customer user not found")
    for key, value in user.dict(exclude_unset=True).items():
        setattr(db_user, key, value)
    db.commit()
    db.refresh(db_user)
    return db_user


@app.delete("/customer-users/{user_id}", dependencies=[Depends(verify_api_key)])
def delete_customer_user(user_id: int, db: Session = Depends(get_db)):
    db_user = db.query(CustomerUserModel).get(user_id)
    if not db_user:
        raise HTTPException(status_code=404, detail="Customer user not found")
    db.delete(db_user)
    db.commit()
    return {"message": "Customer user deleted"}


# ----------------- Management -----------------
@app.post("/managements", dependencies=[Depends(verify_api_key)])
def create_management(management: ManagementCreate, db: Session = Depends(get_db)):
    keys = generate_rsa_key_pair()
    db_mgmt = Management(
        **management.dict(),
        private_key=keys["private_key"],
        public_key=keys["public_key"]
    )
    db.add(db_mgmt)
    db.commit()
    db.refresh(db_mgmt)
    return db_mgmt


@app.get("/managements", dependencies=[Depends(verify_api_key)])
def list_managements(db: Session = Depends(get_db)):
    return db.query(Management).all()


@app.put("/managements/{management_id}", dependencies=[Depends(verify_api_key)])
def update_management(management_id: int, management: ManagementUpdate, db: Session = Depends(get_db)):
    db_mgmt = db.query(Management).get(management_id)
    if not db_mgmt:
        raise HTTPException(status_code=404, detail="Management not found")
    for key, value in management.dict(exclude_unset=True).items():
        setattr(db_mgmt, key, value)
    db.commit()
    db.refresh(db_mgmt)
    return db_mgmt


@app.delete("/managements/{management_id}", dependencies=[Depends(verify_api_key)])
def delete_management(management_id: int, db: Session = Depends(get_db)):
    db_mgmt = db.query(Management).get(management_id)
    if not db_mgmt:
        raise HTTPException(status_code=404, detail="Management not found")
    db.delete(db_mgmt)
    db.commit()
    return {"message": "Management deleted"}


# ----------------- Management Users -----------------
@app.post("/management-users", dependencies=[Depends(verify_api_key)])
def create_management_user(user: ManagementUserCreate, db: Session = Depends(get_db)):
    db_user = ManagementUserModel(**user.dict())
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user


@app.get("/management-users", dependencies=[Depends(verify_api_key)])
def list_management_users(management_id: int = None, db: Session = Depends(get_db)):
    query = db.query(ManagementUserModel)
    if management_id is not None:
        query = query.filter(ManagementUserModel.management_id == management_id)
    return query.all()


@app.put("/management-users/{user_id}", dependencies=[Depends(verify_api_key)])
def update_management_user(user_id: int, user: ManagementUserUpdate, db: Session = Depends(get_db)):
    db_user = db.query(ManagementUserModel).get(user_id)
    if not db_user:
        raise HTTPException(status_code=404, detail="Management user not found")
    for key, value in user.dict(exclude_unset=True).items():
        setattr(db_user, key, value)
    db.commit()
    db.refresh(db_user)
    return db_user


@app.delete("/management-users/{user_id}", dependencies=[Depends(verify_api_key)])
def delete_management_user(user_id: int, db: Session = Depends(get_db)):
    db_user = db.query(ManagementUserModel).get(user_id)
    if not db_user:
        raise HTTPException(status_code=404, detail="Management user not found")
    db.delete(db_user)
    db.commit()
    return {"message": "Management user deleted"}


# ----------------- Machines -----------------
@app.post("/machines", dependencies=[Depends(verify_api_key)])
def create_machine(machine: MachineCreate, db: Session = Depends(get_db)):
    db_machine = MachineModel(**machine.dict())
    db.add(db_machine)
    db.commit()
    db.refresh(db_machine)
    return db_machine


@app.get("/machines", dependencies=[Depends(verify_api_key)])
def list_machines(db: Session = Depends(get_db)):
    return db.query(MachineModel).all()


@app.put("/machines/{machine_id}", dependencies=[Depends(verify_api_key)])
def update_machine(machine_id: int, machine: MachineUpdate, db: Session = Depends(get_db)):
    db_machine = db.query(MachineModel).get(machine_id)
    if not db_machine:
        raise HTTPException(status_code=404, detail="Machine not found")
    for key, value in machine.dict(exclude_unset=True).items():
        setattr(db_machine, key, value)
    db.commit()
    db.refresh(db_machine)
    return db_machine


@app.delete("/machines/{machine_id}", dependencies=[Depends(verify_api_key)])
def delete_machine(machine_id: int, db: Session = Depends(get_db)):
    db_machine = db.query(MachineModel).get(machine_id)
    if not db_machine:
        raise HTTPException(status_code=404, detail="Machine not found")
    db.delete(db_machine)
    db.commit()
    return {"message": "Machine deleted"}


# ----------------- Serial Numbers -----------------
@app.post("/serials", dependencies=[Depends(verify_api_key)])
def create_serial(serial: SerialCreate, db: Session = Depends(get_db)):
    # Validation: user must not send both days and count
    # if serial.license_type.lower() == "trial" and serial.days and serial.count:
    #     raise HTTPException(status_code=400, detail="Only one of 'days' or 'count' can be entered for Trial license")

    # Set initial and last updated dates to current date
    # current_date = datetime.now().strftime("%Y-%m-%d")

    # 1️⃣ Check if serial number already exists, set all `key_expire` to "false"
    # existing_serials = (
    #     db.query(SerialNumbers)
    #     .filter(SerialNumbers.serial_number == serial.serial_number)
    #     .all()
    # )
    #
    # for item in existing_serials:
    #     item.key_expire = "false"
    #     db.add(item)

    # Generate a 16-byte key here
    # generated_key = generate_16char_key()

    db_serial = SerialNumbers(
        serial_number=serial.serial_number,
        date_of_manufacturing=serial.date_of_manufacturing,
        additional_warranty_months=str(serial.additional_warranty_months),
        warranty_end_date=serial.warranty_end_date,
        model_number=serial.model_number,
        customer_id=serial.customer_id,
    )

    db.add(db_serial)
    db.commit()
    db.refresh(db_serial)

    # ✅ Add to SerialHistory (log)
    # db_history = SerialHistory(
    #     serial_id=db_serial.id,
    #     customer_id=db_serial.customer_id,
    #     model_number=db_serial.model_number,
    #     serial_number=db_serial.serial_number,
    #     license_type=db_serial.license_type,
    #     days=db_serial.days,
    #     count=db_serial.count,
    #     initial_date=db_serial.initial_date,
    #     last_updated=db_serial.last_updated,
    # )
    # db.add(db_history)
    # db.commit()

    return db_serial


@app.get("/serials", dependencies=[Depends(verify_api_key)])
def list_serials(db: Session = Depends(get_db)):
    return db.query(SerialNumbers).all()


@app.put("/serials/{serial_id}", dependencies=[Depends(verify_api_key)])
def update_serial(serial_id: int, serial: SerialUpdate, db: Session = Depends(get_db)):
    db_serial = db.query(SerialNumbers).get(serial_id)
    if not db_serial:
        raise HTTPException(status_code=404, detail="Serial number not found")

    # Validation: only one of days/count can be updated
    # if serial.days and serial.count:
    #     raise HTTPException(status_code=400, detail="Only one of 'days' or 'count' can be updated")
    #
    # # Track whether we need to add a SerialHistory record
    # should_add_history = False
    #
    # # Check if license_type / days / count are changing
    # if serial.license_type is not None:
    #     should_add_history = True
    # if serial.days is not None:
    #     should_add_history = True
    # if serial.count is not None:
    #     should_add_history = True

    # print("License", serial.license_type)
    # print("Days", serial.days)
    # print("Count", serial.count)
    # print("should_add_history", should_add_history)

    # Apply updates (skip overwriting status)
    for key, value in serial.dict(exclude_unset=True).items():
        # if key == "status":
        #     continue
        setattr(db_serial, key, value)

    # Update status after applying other fields
    # if should_add_history:
    #     db_serial.status = "Active"

    # Always update last_updated
    # db_serial.last_updated = datetime.now().strftime("%Y-%m-%d")

    db.commit()
    db.refresh(db_serial)

    # ✅ Only add SerialHistory if relevant fields changed
    # if should_add_history:
    #     db_history = SerialHistory(
    #         serial_id=db_serial.id,
    #         customer_id=db_serial.customer_id,
    #         model_number=db_serial.model_number,
    #         serial_number=db_serial.serial_number,
    #         license_type=db_serial.license_type,
    #         days=db_serial.days,
    #         count=db_serial.count,
    #         initial_date=db_serial.initial_date,
    #         last_updated=db_serial.last_updated,
    #     )
    #     db.add(db_history)
    #     db.commit()

    return db_serial


@app.delete("/serials/{serial_id}", dependencies=[Depends(verify_api_key)])
def delete_serial(serial_id: int, db: Session = Depends(get_db)):
    db_serial = db.query(SerialNumbers).get(serial_id)
    if not db_serial:
        raise HTTPException(status_code=404, detail="Serial number not found")
    db.delete(db_serial)
    db.commit()
    return {"message": "Serial number deleted"}


@app.post("/software_key", dependencies=[Depends(verify_api_key)])
def create_software_key(serial: SoftwareKeyCreate, db: Session = Depends(get_db)):
    generated_key = generate_16char_key()

    db_serial = SoftwareKey(
        serial_number=serial.serial_number,
        sw_version=serial.sw_version,
        pcb_version=serial.pcb_version,
        fw_version=serial.fw_version,
        design_version=serial.design_version,
        license_type=serial.license_type,
        initial_date=serial.initial_date,
        last_updated=serial.last_updated,
        parameter=serial.parameter,
        software_key=generated_key,
        reason=serial.reason,
    )

    db.add(db_serial)
    db.commit()
    db.refresh(db_serial)

    return db_serial


@app.get("/software_key", dependencies=[Depends(verify_api_key)])
def list_software_key(db: Session = Depends(get_db)):
    return db.query(SoftwareKey).all()


@app.put("/software_key/{key_id}", dependencies=[Depends(verify_api_key)])
def update_software_key(key_id: int, serial: SoftwareKeyUpdate, db: Session = Depends(get_db)):
    db_serial = db.query(SoftwareKey).get(key_id)
    if not db_serial:
        raise HTTPException(status_code=404, detail="Software Key not found")

    # Apply updates (skip overwriting status)
    for key, value in serial.dict(exclude_unset=True).items():
        setattr(db_serial, key, value)

    db.commit()
    db.refresh(db_serial)

    return db_serial


@app.delete("/software_key/{key_id}", dependencies=[Depends(verify_api_key)])
def delete_software_key(key_id: int, db: Session = Depends(get_db)):
    db_serial = db.query(SoftwareKey).get(key_id)
    if not db_serial:
        raise HTTPException(status_code=404, detail="Software Key not found")
    db.delete(db_serial)
    db.commit()
    return {"message": "Software-Key deleted"}


@app.get("/serial_exists/{serial_number}", response_model=bool, dependencies=[Depends(verify_api_key)])
def check_serial_exists(serial_number: str, db: Session = Depends(get_db)):
    return db.query(SerialNumbers).filter(SerialNumbers.serial_number == serial_number).first() is not None


@app.get("/serials/{serial_id}/history", dependencies=[Depends(verify_api_key)])
def get_serial_history(serial_id: int, db: Session = Depends(get_db)):
    history = (
        db.query(SerialHistory)
        .filter(SerialHistory.serial_id == serial_id)
        .order_by(SerialHistory.recorded_at.desc())
        .all()
    )
    return history


@app.get("/serials/history", dependencies=[Depends(verify_api_key)])
def get_all_history(db: Session = Depends(get_db)):
    history = db.query(SerialHistory).order_by(SerialHistory.recorded_at.desc()).all()
    return history


@app.post("/create_license/{customer_id}", dependencies=[Depends(verify_api_key)])
def create_or_update_license(
    customer_id: int,
    payload: EncryptedLicenseCreate,
    db: Session = Depends(get_db)
):
    """Create or update license using hybrid AES+RSA encryption with controller modules"""

    # 1️⃣ Fetch customer and private key
    customer = db.query(Customer).filter(Customer.id == customer_id).first()
    if not customer:
        raise HTTPException(status_code=404, detail="Customer not found")
    if not customer.private_key:
        raise HTTPException(status_code=400, detail="Customer private key not found")

    # 2️⃣ Decrypt AES key with RSA
    try:
        private_key = RSA.import_key(customer.private_key)
        rsa_cipher = PKCS1_OAEP.new(private_key)
        aes_key_bytes = rsa_cipher.decrypt(base64.b64decode(payload.encrypted_key))

        iv = base64.b64decode(payload.iv)
        encrypted_data = base64.b64decode(payload.encrypted_data)
        aes_cipher = AES.new(aes_key_bytes, AES.MODE_CBC, iv)
        decrypted_bytes = unpad(aes_cipher.decrypt(encrypted_data), AES.block_size)
        decrypted_json = json.loads(decrypted_bytes.decode("utf-8"))
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Decryption failed: {str(e)}")

    # 3️⃣ Validate required fields
    required_fields = [
        "mother_board_serial",
        "enabled_machines",
        "hmi_model_no", "hmi_serial_no", "hmi_license_status", "hmi_key",
        "flow_model_no", "flow_serial_no", "flow_license_status", "flow_key",
        "chem_chef_model_no", "chem_chef_serial_no", "chem_chef_license_status", "chem_chef_key",
        "dye_weigh_model_no", "dye_weigh_serial_no", "dye_weigh_license_status", "dye_weigh_key",
        "dye_prep_model_no", "dye_prep_serial_no", "dye_prep_license_status", "dye_prep_key",
        "dye_asrs_model_no", "dye_asrs_serial_no", "dye_asrs_license_status", "dye_asrs_key",
        "auxi_prep_model_no", "auxi_prep_serial_no", "auxi_prep_license_status", "auxi_prep_key",
        "auxi_disp_model_no", "auxi_disp_serial_no", "auxi_disp_license_status", "auxi_disp_key",
        "client_public_key",
        "controller_modules"
    ]
    for f in required_fields:
        if f not in decrypted_json:
            raise HTTPException(status_code=400, detail=f"Missing field: {f}")

    # 3a️⃣ Validate client public key
    try:
        cleaned_pub_key = clean_public_key(decrypted_json["client_public_key"])
        validate_rsa_public_key(cleaned_pub_key)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    # 4️⃣ Process enabled machines
    enabled_machines = decrypted_json["enabled_machines"]
    if not isinstance(enabled_machines, list):
        raise HTTPException(status_code=400, detail="enabled_machines must be a list")

    # 5️⃣ Validate customer's serial numbers
    serials = db.query(SerialNumbers).filter(SerialNumbers.customer_id == customer_id).all()
    if not serials:
        raise HTTPException(status_code=400, detail="No serial numbers found for this customer")

    # 6️⃣ Verify machine associations
    machine_checks = [
        ("HMI Network", decrypted_json["hmi_model_no"], decrypted_json["hmi_serial_no"]),
        ("Flow Dispenser", decrypted_json["flow_model_no"], decrypted_json["flow_serial_no"]),
        ("ChemChef Dispenser", decrypted_json["chem_chef_model_no"], decrypted_json["chem_chef_serial_no"]),
        ("Dye Weighing System", decrypted_json["dye_weigh_model_no"], decrypted_json["dye_weigh_serial_no"]),
        ("Dye Preparation System", decrypted_json["dye_prep_model_no"], decrypted_json["dye_prep_serial_no"]),
        ("Dye ASRS System", decrypted_json["dye_asrs_model_no"], decrypted_json["dye_asrs_serial_no"]),
        ("Auxiliary Preparation System", decrypted_json["auxi_prep_model_no"], decrypted_json["auxi_prep_serial_no"]),
        ("Auxiliary Dispenser System", decrypted_json["auxi_disp_model_no"], decrypted_json["auxi_disp_serial_no"]),
    ]
    for machine_name, model_no, serial_no in machine_checks:
        if machine_name not in enabled_machines:
            continue
        serial_record = (
            db.query(SerialNumbers)
            .join(MachineModel, SerialNumbers.model_number == MachineModel.id)
            .filter(
                SerialNumbers.customer_id == customer_id,
                MachineModel.model_number == model_no,
                SerialNumbers.serial_number == serial_no,
            )
            .first()
        )
        if not serial_record:
            raise HTTPException(
                status_code=400,
                detail=f"{machine_name}: Model/Serial mismatch or not linked to this customer"
            )

    # 7️⃣ Update serials if license_status == "Expiry"
    license_status_mappings = [
        ("hmi_license_status", decrypted_json["hmi_serial_no"]),
        ("flow_license_status", decrypted_json["flow_serial_no"]),
        ("chem_chef_license_status", decrypted_json["chem_chef_serial_no"]),
        ("dye_weigh_license_status", decrypted_json["dye_weigh_serial_no"]),
        ("dye_prep_license_status", decrypted_json["dye_prep_serial_no"]),
        ("dye_asrs_license_status", decrypted_json["dye_asrs_serial_no"]),
        ("auxi_prep_license_status", decrypted_json["auxi_prep_serial_no"]),
        ("auxi_disp_license_status", decrypted_json["auxi_disp_serial_no"]),
    ]

    for status_field, serial_no in license_status_mappings:
        status_value = decrypted_json.get(status_field)
        if status_value and status_value.lower() == "expiry":
            serial_record = (
                db.query(SerialNumbers)
                .filter(
                    SerialNumbers.customer_id == customer_id,
                    SerialNumbers.serial_number == serial_no,
                )
                .first()
            )
            if serial_record and serial_record.client_last_update != "":
                serial_record.status = "Expiry"
                serial_record.client_last_update = ""
                db.add(serial_record)

    # 8️⃣ Save/update controller modules
    controller_modules_list = decrypted_json.get("controller_modules", [])
    if not isinstance(controller_modules_list, list):
        raise HTTPException(status_code=400, detail="controller_modules must be a list")

    # Delete previous modules for this customer
    db.query(ControllerModules).filter(ControllerModules.customer_id == customer_id).delete()

    for module in controller_modules_list:
        # Validate required fields in each module
        for field in ["DeviceName", "DeviceUID", "FW_Version_No", "FW_Build_No", "Model_No", "ID"]:
            if field not in module:
                raise HTTPException(status_code=400, detail=f"Missing {field} in controller_modules")

        new_module = ControllerModules(
            customer_id=customer_id,
            device_name=module["DeviceName"],
            device_uid=module["DeviceUID"],
            fw_version_no=module["FW_Version_No"],
            fw_build_no=module["FW_Build_No"],
            model_number=module["Model_No"],
            controller_id=module["ID"],
        )
        db.add(new_module)

    # 6️⃣ Serial + Key matching check
    serial_key_mappings = [
        ("HMI Network", "hmi_serial_no", "hmi_key"),
        ("Flow Dispenser", "flow_serial_no", "flow_key"),
        ("ChemChef Dispenser", "chem_chef_serial_no", "chem_chef_key"),
        ("Dye Weighing System", "dye_weigh_serial_no", "dye_weigh_key"),
        ("Dye Preparation System", "dye_prep_serial_no", "dye_prep_key"),
        ("Dye ASRS System", "dye_asrs_serial_no", "dye_asrs_key"),
        ("Auxiliary Preparation System", "auxi_prep_serial_no", "auxi_prep_key"),
        ("Auxiliary Dispenser System", "auxi_disp_serial_no", "auxi_disp_key"),
    ]

    # 8️⃣ Match serials, update SerialNumbers, and build response list
    matched_serials_response = []

    for machine_name, serial_field, key_field in serial_key_mappings:
        serial_no = decrypted_json.get(serial_field)
        key_val = decrypted_json.get(key_field)

        # Find serial in DB
        serial_record = (
            db.query(SerialNumbers)
            .filter(
                SerialNumbers.customer_id == customer_id,
                SerialNumbers.serial_number == serial_no
            )
            .first()
        )

        if not serial_record:
            raise HTTPException(status_code=400, detail=f"{machine_name}: Serial not found")

        if serial_record.key_expire == "true":
            raise HTTPException(status_code=400, detail=f"{key_field}: not matching")

        if serial_record.software_key != key_val:
            raise HTTPException(status_code=400, detail=f"{machine_name}: Key mismatch")

        # # 7️⃣ Controller modules validation
        # controller_modules_list = decrypted_json.get("controller_modules", [])
        # if not isinstance(controller_modules_list, list):
        #     raise HTTPException(status_code=400, detail="controller_modules must be a list")
        #
        # # Update SerialNumbers with controller module info
        # if controller_modules_list:
        #     module = controller_modules_list[0]  # Use first module or choose based on UID
        #     serial_record.device_name = module["device_name"]
        #     serial_record.device_uid = module["device_uid"]
        #     serial_record.fw_build_no = module["FW_Build_No"]
        #     serial_record.reason = "0"

        matched_serials_response.append({
            "machine": machine_name,
            "serial_no": serial_no,
            "key": key_val,
            "license_type": serial_record.license_type,
            "days": serial_record.days,
            "count": serial_record.count,
            "status": serial_record.status,
            "software_version": serial_record.sw_version,
            # "client_last_update": serial_record.client_last_update,
            # "device_name": serial_record.device_name,
            # "device_uid": serial_record.device_uid,
            # "fw_build_no": serial_record.fw_build_no,
            # "fw_version": serial_record.fw_version,
        })

        db.add(serial_record)

    # # 9️⃣ Delete old license rows and create new
    # db.query(LicenseData).filter(LicenseData.customer_id == customer_id).delete()
    # for machine_name in enabled_machines:
    #     new_license = LicenseData(
    #         customer_id=customer_id,
    #         mother_board_serial=decrypted_json["mother_board_serial"],
    #         client_public_key=cleaned_pub_key,
    #         enabled_machines=machine_name
    #     )
    #     db.add(new_license)
    #
    # db.commit()

    # 9️⃣ Delete old license rows and create new with serial_no + key_val
    db.query(LicenseData).filter(LicenseData.customer_id == customer_id).delete()

    for item in matched_serials_response:
        new_license = LicenseData(
            customer_id=customer_id,
            mother_board_serial=decrypted_json["mother_board_serial"],
            client_public_key=cleaned_pub_key,
            enabled_machines=item["machine"],
            serial_no=item["serial_no"],  # ✅ Save serial_no
            key_val=item["key"],  # ✅ Save key
        )
        db.add(new_license)

    db.commit()

    license_records = db.query(LicenseData).filter(LicenseData.customer_id == customer_id).all()
    if not license_records:
        raise HTTPException(status_code=404, detail="No license found for this customer")

    # Assume all records share same mother_board_serial and public_key
    mother_board_serial = license_records[0].mother_board_serial

    if decrypted_json["mother_board_serial"] != mother_board_serial:
        raise HTTPException(status_code=404, detail="Device Mother Board Serial Number mismatch")

    # 🔟 Encrypt final response with client public key
    plain_json = json.dumps({
        "customer_id": str(customer_id),
        "mother_board_serial": mother_board_serial,
        "enabled_machines": enabled_machines,
        "matched_serials": matched_serials_response,
        "controller_modules": controller_modules_list,
        "status": "Active",
    })

    encrypted_output = encrypt_with_public_key_hybrid(cleaned_pub_key, plain_json)

    return encrypted_output

    # return {
    #     "status": "created_or_updated",
    #     "message": "License and controller modules saved successfully",
    #     "enabled_machines": enabled_machines,
    #     "controller_modules_count": len(controller_modules_list)
    # }


def pkcs7_pad(data: bytes, block_size: int = 16) -> bytes:
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len] * pad_len)


def clean_public_key(pem_str: str) -> str:
    pem_lines = [line.strip() for line in pem_str.strip().splitlines() if line.strip()]

    if not pem_lines:
        raise ValueError("Empty public key provided")

    header = pem_lines[0]
    footer = pem_lines[-1]

    # Determine key type by header
    if "RSA PUBLIC KEY" in header:
        if not header.startswith("-----BEGIN RSA PUBLIC KEY-----"):
            pem_lines.insert(0, "-----BEGIN RSA PUBLIC KEY-----")
        if not footer.startswith("-----END RSA PUBLIC KEY-----"):
            pem_lines.append("-----END RSA PUBLIC KEY-----")
    else:
        if not header.startswith("-----BEGIN PUBLIC KEY-----"):
            pem_lines.insert(0, "-----BEGIN PUBLIC KEY-----")
        if not footer.startswith("-----END PUBLIC KEY-----"):
            pem_lines.append("-----END PUBLIC KEY-----")

    return "\n".join(pem_lines)


def validate_rsa_public_key(pem_str: str) -> RSA.RsaKey:
    try:
        key = RSA.import_key(pem_str)

        # Public key must have 'n' and 'e', and must NOT have 'd'
        if not hasattr(key, "n") or not hasattr(key, "e") or hasattr(key, "d"):
            raise ValueError("Provided key is not a valid RSA public key")

        return key
    except (ValueError, IndexError, TypeError) as e:
        raise ValueError(f"Invalid user-supplied public key: {e}")


def encrypt_with_public_key_hybrid(public_key_pem: str, json_data: str) -> dict:
    # Clean and validate public key
    cleaned_key = clean_public_key(public_key_pem)
    public_key = validate_rsa_public_key(cleaned_key)

    # 1️⃣ Generate AES key & IV
    aes_key = get_random_bytes(32)  # AES-256
    iv = get_random_bytes(16)

    # 2️⃣ Encrypt JSON with AES-CBC + PKCS7 padding
    data_bytes = pkcs7_pad(json_data.encode("utf-8"))
    cipher_aes = AES.new(aes_key, AES.MODE_CBC, iv)
    encrypted_data = cipher_aes.encrypt(data_bytes)

    # 3️⃣ Encrypt AES key with RSA-OAEP
    cipher_rsa = PKCS1_OAEP.new(public_key)
    encrypted_key = cipher_rsa.encrypt(aes_key)

    # 4️⃣ Return base64-encoded values
    return {
        "encrypted_key": base64.b64encode(encrypted_key).decode("utf-8"),
        "encrypted_data": base64.b64encode(encrypted_data).decode("utf-8"),
        "iv": base64.b64encode(iv).decode("utf-8"),
    }


@app.get("/fetch_license/{customer_id}/{mother_board_serial_number}", dependencies=[Depends(verify_api_key)])
def get_license_info(customer_id: int, mother_board_serial_number: str, db: Session = Depends(get_db)):
    # Fetch all license records for the customer
    license_records = db.query(LicenseData).filter(LicenseData.customer_id == customer_id).all()
    if not license_records:
        raise HTTPException(status_code=404, detail="No license found for this customer")

    # Assume all records share same mother_board_serial and public_key
    mother_board_serial = license_records[0].mother_board_serial
    client_public_key = license_records[0].client_public_key
    serial_number = license_records[0].serial_no
    key_value = license_records[0].key_val

    if mother_board_serial_number != license_records[0].mother_board_serial:
        raise HTTPException(status_code=404, detail="Device Mother Board Serial Number mismatch")

    # Collect enabled machine names from multiple rows
    all_enabled_machines = [l.enabled_machines for l in license_records if l.enabled_machines]

    # 🔹 Fetch only serials for this customer whose machine name is in enabled_machines
    # serials = (
    #     db.query(SerialNumbers)
    #     .join(MachineModel, SerialNumbers.model_number == MachineModel.id)
    #     .filter(
    #         SerialNumbers.customer_id == customer_id,
    #         MachineModel.machineName.in_([m.strip() for m in all_enabled_machines])
    #     )
    #     .all()
    # )

    serials = (
        db.query(SerialNumbers)
        .filter(
            SerialNumbers.customer_id == customer_id, SerialNumbers.serial_number == serial_number,
            SerialNumbers.key == key_value, SerialNumbers.key_expire == "true")
        .all()
    )

    # Filter serials with status == "Active" and client_last_update empty
    eligible_serials = [s for s in serials if s.status == "Active" and not s.client_last_update]

    if eligible_serials:
        # Update client_last_update for eligible serials to today's date
        today_str = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
        for s in eligible_serials:
            s.client_last_update = today_str
            db.add(s)
        db.commit()
    # else:

    # Build list of serial details
    serial_details_list = []
    for s in serials:
        serial_details_list.append({
            "serial_no": s.serial_number,
            "license_type": s.license_type,
            "key": s.software_key,
            "days": s.days,
            "count": s.count,
            "status": s.status,
            "software_version": s.sw_version,
            "machine": s.machine_model.machineName,
            # "client_last_update": s.client_last_update,
            # "device_name": s.device_name,
            # "device_uid": s.device_uid,
            # "fw_version": s.fw_version,
            # "fw_build_no": s.fw_build_no,
        })

    controller_modules_details = (db.query(ControllerModules).filter(ControllerModules.customer_id == customer_id).all())

    controller_modules_list = []
    for modules in controller_modules_details:
        controller_modules_list.append({
            "DeviceName": modules.device_name,
            "DeviceUID": modules.device_uid,
            "FW_Version_No": modules.fw_version_no,
            "FW_Build_No": modules.fw_build_no,
            "Model_No": modules.model_number,
            "ID": modules.controller_id,

        })
    # Final response
    response_data = {
        "customer_id": str(customer_id),
        "mother_board_serial": mother_board_serial,
        "enabled_machines": all_enabled_machines,
        "matched_serials": serial_details_list,
        "controller_modules": controller_modules_list,
        "status": "Active"
    }

    # Encrypt
    try:
        encrypted_response = encrypt_with_public_key_hybrid(
            client_public_key,
            json.dumps(response_data)
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Encryption failed: {str(e)}")

    return encrypted_response


@app.get("/license_data", dependencies=[Depends(verify_api_key)])
def get_all_license_data(db: Session = Depends(get_db)):
    all_license_data = db.query(LicenseData).all()
    return all_license_data


@app.get("/controller_modules_data", dependencies=[Depends(verify_api_key)])
def get_all_controller_modules_data(db: Session = Depends(get_db)):
    all_controller_modules_data = db.query(ControllerModules).all()
    return all_controller_modules_data


@app.delete("/licenses/{license_id}", dependencies=[Depends(verify_api_key)])
def delete_license(license_id: int, db: Session = Depends(get_db)):
    db_license = db.query(LicenseData).get(license_id)
    if not db_license:
        raise HTTPException(status_code=404, detail="License not found")
    db.delete(db_license)
    db.commit()
    return {"message": "License deleted"}


# ----------------- Main -----------------
if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8001)
