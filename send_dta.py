# # import requests
# #
# # url = "http://157.173.222.91:8001/customers"
# # headers = {
# #     "accept": "application/json",
# #     "Content-Type": "application/json",
# #     "x-api-key": "My_Server_API_Key-123"
# # }
# # data = {
# #     "name": "Alice Test",
# #     "phone": "9998887777",
# #     "email": "alice@test.com",
# #     "gst": "GST1234",
# #     "latitude": "12.34",
# #     "longitude": "56.78",
# #     "address": "123 Test Street",
# #     "key_name": "key_alice"
# # }
# #
# # r = requests.post(url, json=data, headers=headers)
# # print(r.status_code, r.json())
#
#
# import requests
#
# url = "http://157.173.222.91:8001/customer-users"  # Your endpoint
# headers = {
#     "accept": "application/json",
#     "Content-Type": "application/json",
#     "x-api-key": "My_Server_API_Key-123"
# }
#
# data = {
#     "name": "John Doe",
#     "username": "john_doe",
#     "password": "123456",
#     "designation": "Technician",
#     "privilege": "admin",  # or "user"
#     "customer_id": 1  # Must match an existing customer ID
# }
#
# response = requests.post(url, json=data, headers=headers)
# print(response.status_code, response.json())
#
# data1 = {
#   "customer_id": 1,
#   "mother_board_serial": "MB-ABC-123",
#   "enabled_machines": ["HMI", "FlowI", "ChemChef"],
#   "machines": [
#     {
#       "machine_name": "HMI",
#       "license_type": "Trial",
#       "start_date": "2025-10-01",
#       "end_date": "2025-10-31"
#     },
#     {
#       "machine_name": "FlowI",
#       "license_type": "Perpetual",
#       "start_date": "",
#       "end_date": ""
#     },
#     {
#       "machine_name": "ChemChef",
#       "license_type": "Complete",
#       "start_date": "",
#       "end_date": ""
#     }
#   ]
# }

from Cryptodome.PublicKey import RSA

# Generate 2048-bit RSA key
key = RSA.generate(2048)

private_key_pem = key.export_key().decode()
public_key_pem = key.publickey().export_key().decode()

print("PRIVATE KEY:\n", private_key_pem)
print("PUBLIC KEY:\n", public_key_pem)

