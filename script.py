import json
import email
import smtplib
from email.message import EmailMessage

user = input("enter your email: ")
password = input("enter your password: ")
receiver = input("email of the person you want to receive your email: ")
smtp_con = input("your domain for smtp (example: smtp.yourdomain.com): ")

# send email to user
def send_email(email, password, smtp, receiver_email, body):
    msg = EmailMessage()
    msg['Subject'] = "message"
    msg['From'] = email
    msg['To'] = receiver_email
    msg.set_content(body)
    with smtplib.SMTP_SSL(smtp, 465) as smtp: # more secure way to send message
        smtp.login(email, password)
        smtp.send_message(msg)

# extracting all open ports from json into a message       
def message():
    warnings = """
    Scanning all Security groups for open ports 
    ----------------------------------------------------------"""
    with open('sg_list_full.json') as jsonData:
        jsonObject = json.load(jsonData)
        for sg in jsonObject['SecurityGroups']:
            for ip in sg["IpPermissions"]:
                if "ToPort" in ip:
                    if ip["ToPort"] != 443 and ip["IpProtocol"] == "tcp":
                        for cidr in ip["IpRanges"]:
                            if cidr["CidrIp"] == "0.0.0.0/0":
                                message = f"""
    Warning: found potentail security hole in {sg["GroupId"]}
    ---> Inbound rule: Protocol {ip["IpProtocol"]} {ip["ToPort"]} is open for CIDR {cidr["CidrIp"]}
    -----------------------------------------------------------"""
                                warnings += message
    jsonData.close()
    return warnings

# sending the message() output to user using the send_email()
def main():
    msg = message()
    print(msg)
    print("sending email to email")
    send_email(user, password, smtp_con, receiver, msg)

if __name__ == "__main__":
    main()
