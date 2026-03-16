# AWS Free Tier Deployment Guide: Security-as-a-Service API

Now that your Machine Learning Risk Engine is refactored into a scalable, multi-tenant API, it is ready to be hosted on the cloud. By following these steps, your Flask app (`app.py`) will be able to run anywhere in the world and securely call your Cloud ML API.

## Step 1: Set up AWS RDS (PostgreSQL)
Currently, `api_db.db` is a local SQLite file. This won't work in a distributed cloud environment where the container might restart or scale.

1.  Log into the AWS Management Console and navigate to **RDS**.
2.  Click **Create database**.
3.  Choose **PostgreSQL**.
4.  **CRITICAL**: Under Templates, select **Free tier** to avoid charges.
5.  Set your DB instance identifier (e.g., `risk-engine-db`), Master username (e.g., `postgres`), and Master password.
6.  Under Connectivity, choose **Publicly accessible: Yes** (for easier initial testing) and create a new VPC security group that allows inbound traffic on port `5432` from your IP address and the EC2 instance's security group.
7.  Once the database is created, copy the **Endpoint** URL.

## Step 2: Update `ml_service.py` for PostgreSQL
Before deploying, you need to change your `sqlite3` connection in `ml_service.py` to use `psycopg2` (which you will need to add to `requirements_ml.txt`) and point to your new RDS endpoint:

```python
import psycopg2
import os

def get_api_db():
    # Fetch from Environment Variables configured on the EC2 server
    return psycopg2.connect(
        host=os.environ.get("DB_HOST", "localhost"), # Your RDS Endpoint
        database=os.environ.get("DB_NAME", "postgres"),
        user=os.environ.get("DB_USER", "postgres"),
        password=os.environ.get("DB_PASSWORD", "secret")
    )
```

## Step 3: Launch an EC2 Instance (The Server)
This is where your Docker container will actually run.

1.  Navigate to **EC2** in the AWS Console.
2.  Click **Launch instance**.
3.  Name it `risk-engine-api`.
4.  Choose the **Amazon Linux 2023 AMI** (Free tier eligible).
5.  Instance type: **t2.micro** (Free tier eligible).
6.  Create a new key pair (download the `.pem` file) so you can SSH into the server later.
7.  Network settings: Create a security group that allows **SSH traffic from Anywhere** and **Custom TCP traffic on port 6000 from Anywhere**.
8.  Click **Launch instance**.

## Step 4: Deploy the Docker Container
Once the EC2 instance is running, connect to it.

1.  SSH into your instance using the key pair:
    `ssh -i "your-key.pem" ec2-user@<your-ec2-public-ip>`
2.  Install Git and Docker on the EC2 instance:
    ```bash
    sudo yum update -y
    sudo yum install docker git -y
    sudo service docker start
    sudo usermod -a -G docker ec2-user
    ```
    *(Log out and log back in for docker permissions to apply)*
3.  Clone your code repository containing `ml_service.py`, `Dockerfile_ml`, and `requirements_ml.txt` onto the server.
4.  Build the Docker image:
    `docker build -f Dockerfile_ml -t risk-api .`
5.  Run the container in the background, passing in your secure environment variables:
    ```bash
    docker run -d -p 6000:6000 \
      -e DB_HOST="your-rds-endpoint" \
      -e DB_USER="postgres" \
      -e DB_PASSWORD="your-secure-password" \
      -e DB_NAME="postgres" \
      -e FLASK_SECRET_KEY="your-random-secret" \
      risk-api
    ```

## Step 5: Test the Cloud Integration
1. Go back to your local `app.py` file on your laptop.
2. Find the code in the `/behavior` endpoint that calls the ML microservice.
3. Replace the local loopback URL `127.0.0.1` with the Public IP of your new EC2 Instance.
   ```python
   ml_response = requests.post(
       "http://<your-ec2-public-ip>:6000/evaluate",
       ...
   )
   ```

Congratulations! Your local machine is now sending real-time keystroke and mouse telemetry across the internet to a live Cloud Behavioral Risk Engine.
