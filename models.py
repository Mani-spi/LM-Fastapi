from enum import Enum
from sqlalchemy import Column, Integer, String, DateTime, Text, ForeignKey
from sqlalchemy.orm import relationship, declarative_base
from datetime import datetime
from database import Base


# Privilege Enums
class ManagementPrivilegeEnum(str, Enum):
    Admin = "Admin"
    Top_Manager = "Top Manager"
    Manager_Production = "Manager-Production"
    Manager_Service = "Manager-Service"
    Service_Engineer = "Service Engineer"


class CustomerPrivilegeEnum(str, Enum):
    Admin = "Admin"
    Manager = "Manager"
    Engineer = "Engineer"
    Lab_Incharge = "Lab Incharge"


# Customers
class Customer(Base):
    __tablename__ = "customers"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(255), nullable=False)
    phone = Column(String(20))
    email = Column(String(255))
    gst = Column(String(50))
    latitude = Column(String(500))
    longitude = Column(String(500))
    address = Column(Text)
    private_key = Column(Text)
    public_key = Column(Text)
    key_name = Column(String(500))

    customer_users = relationship("CustomerUserModel", back_populates="customer", cascade="all, delete")
    customer_serial = relationship("SerialNumbers", back_populates="customer_serial", cascade="all, delete")
    # client_data = relationship("MachineDetails", back_populates="Client", cascade="all, delete")
    licenses = relationship("LicenseData", back_populates="customer", cascade="all, delete")
    controller = relationship("ControllerModules", back_populates="Controller_customer", cascade="all, delete")


# Management
class Management(Base):
    __tablename__ = "management"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(500), nullable=False)
    phone = Column(String(20))
    email = Column(String(100))
    gst = Column(String(500))
    latitude = Column(String(500))
    longitude = Column(String(500))
    address = Column(Text)
    private_key = Column(Text)
    public_key = Column(Text)
    key_name = Column(String(500))

    machines = relationship("MachineModel", back_populates="machineMake", cascade="all, delete")
    management_users = relationship("ManagementUserModel", back_populates="management", cascade="all, delete")


# Users
class ManagementUserModel(Base):
    __tablename__ = "management_user_model"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(500), nullable=False)
    username = Column(String(500), unique=True, nullable=False)
    password = Column(String(500), unique=True, nullable=False)
    designation = Column(String(800), nullable=False)
    privilege = Column(String(500), nullable=False)
    management_id = Column(Integer, ForeignKey("management.id", ondelete="CASCADE"), nullable=False)
    management = relationship("Management", back_populates="management_users")


class CustomerUserModel(Base):
    __tablename__ = "customer_user_model"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(500), nullable=False)
    username = Column(String(500), unique=True, nullable=False)
    password = Column(String(500), unique=True, nullable=False)
    designation = Column(String(800), nullable=False)
    privilege = Column(String(500), nullable=False)
    customer_id = Column(Integer, ForeignKey("customers.id", ondelete="CASCADE"), nullable=False)
    customer = relationship("Customer", back_populates="customer_users")


# Machines
class MachineModel(Base):
    __tablename__ = "machine_model"
    id = Column(Integer, primary_key=True, index=True)
    machineName = Column(String(500), nullable=False)
    model_number = Column(String(500), unique=True, nullable=False)
    description = Column(String(800), nullable=False)
    default_warranty_months = Column(Integer, nullable=False)
    phase = Column(String(20), nullable=False)
    volts = Column(String(500), nullable=False)
    amps = Column(String(500), nullable=False)
    frequency = Column(String(500), nullable=False)
    prefix = Column(String(500))
    make = Column(Integer, ForeignKey("management.id", ondelete="CASCADE"), nullable=False)
    machineMake = relationship("Management", back_populates="machines")
    serial_numbers = relationship("SerialNumbers", back_populates="machine_model", cascade="all, delete-orphan")


# Serial Numbers
class SerialNumbers(Base):
    __tablename__ = "serial_numbers"
    id = Column(Integer, primary_key=True, index=True)
    serial_number = Column(String(500), unique=True, nullable=False)
    date_of_manufacturing = Column(String(500), nullable=False)
    additional_warranty_months = Column(String(500), nullable=False)
    warranty_end_date = Column(String(500), nullable=False)
    product_warranty = Column(String(500), nullable=False)
    model_number = Column(Integer, ForeignKey("machine_model.id", ondelete="CASCADE"), nullable=False)
    machine_model = relationship("MachineModel", back_populates="serial_numbers")
    customer_id = Column(Integer, ForeignKey("customers.id", ondelete="CASCADE"), nullable=False)
    customer_serial = relationship("Customer", back_populates="customer_serial")
    main_serial_numbers = relationship("SoftwareKey", back_populates="machine_serial", cascade="all, delete-orphan")


class SoftwareKey(Base):
    __tablename__ = "software_key"
    id = Column(Integer, primary_key=True, index=True)
    sw_version = Column(String(500))
    pcb_version = Column(String(500))
    fw_version = Column(String(500))
    design_version = Column(String(500))
    license_type = Column(String(100))
    initial_date = Column(String(50))
    last_updated = Column(String(50))
    # client_last_update = Column(String(500))
    parameter = Column(String(50))
    # status = Column(String(500))
    software_key = Column(String(500))
    reason = Column(String(500))
    serial_number = Column(Integer, ForeignKey("serial_numbers.id", ondelete="CASCADE"), nullable=False)
    machine_serial = relationship("SerialNumbers", back_populates="main_serial_numbers")


# License Data
# License Data
# License Data
class LicenseData(Base):
    __tablename__ = "license_data"
    id = Column(Integer, primary_key=True, index=True)
    customer_id = Column(Integer, ForeignKey("customers.id", ondelete="CASCADE"), nullable=False)
    mother_board_serial = Column(String(500), nullable=False)
    client_public_key = Column(Text, nullable=False)
    enabled_machines = Column(String(500), nullable=False)  # Add this to store each machine
    serial_no = Column(String(500))
    key_val = Column(String(500))

    customer = relationship("Customer", back_populates="licenses")


class SerialHistory(Base):
    __tablename__ = "serial_history"

    id = Column(Integer, primary_key=True, index=True)
    serial_id = Column(Integer, index=True)
    customer_id = Column(Integer, nullable=False)
    model_number = Column(Integer, nullable=False)
    serial_number = Column(String(500), nullable=False)
    license_type = Column(String(100), nullable=False)
    days = Column(String(50), nullable=True)
    count = Column(String(50), nullable=True)
    initial_date = Column(String(50), nullable=True)
    last_updated = Column(String(50), nullable=True)
    recorded_at = Column(DateTime, default=datetime.utcnow)


class ControllerModules(Base):
    __tablename__ = "controller_modules"
    id = Column(Integer, primary_key=True, index=True)
    customer_id = Column(Integer, ForeignKey("customers.id", ondelete="CASCADE"), nullable=False)
    device_name = Column(String(500), nullable=False)
    device_uid = Column(String(500), nullable=False)
    fw_version_no = Column(String(500), nullable=False)
    fw_build_no = Column(String(500), nullable=False)
    model_number = Column(Integer, nullable=False)
    controller_id = Column(Integer, nullable=False)

    Controller_customer = relationship("Customer", back_populates="controller")
