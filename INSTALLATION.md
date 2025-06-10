# Installation Guide

## Quick Start

### Step 1: Environment Setup

```bash
# Clone the repository
git clone <repository-url>
cd aws-security-dashboard

# Create virtual environment (recommended)
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

### Step 2: Install Dependencies

The following packages are already installed in this environment:
- streamlit
- boto3
- pandas
- plotly
- pyyaml
- requests
- anthropic
- reportlab
- streamlit-autorefresh
- trafilatura

If running in a new environment, install dependencies using:

```bash
pip install streamlit boto3 pandas plotly pyyaml requests anthropic reportlab streamlit-autorefresh trafilatura
```

### Step 3: AWS Configuration

Configure AWS credentials using one of these methods:

#### Option 1: Environment Variables
```bash
export AWS_ACCESS_KEY_ID=your_access_key
export AWS_SECRET_ACCESS_KEY=your_secret_key
export AWS_DEFAULT_REGION=us-east-1
```

#### Option 2: AWS CLI
```bash
aws configure
```

#### Option 3: Use the Dashboard Interface
Enter credentials directly in the sidebar configuration panel.

### Step 4: Run the Application

```bash
streamlit run app.py --server.port 5000
```

The dashboard will be available at: http://localhost:5000

## Detailed Setup

### System Requirements

- **Operating System**: Windows, macOS, or Linux
- **Python**: 3.11 or higher
- **Memory**: Minimum 4GB RAM (8GB recommended for large AWS environments)
- **Storage**: 2GB free space
- **Network**: Internet connectivity for AWS API calls

### AWS Permissions Setup

Create an IAM policy with the following permissions:

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "iam:*",
                "ec2:Describe*",
                "s3:Get*",
                "s3:List*",
                "kms:List*",
                "kms:Describe*",
                "cloudtrail:Describe*",
                "cloudtrail:LookupEvents",
                "guardduty:List*",
                "guardduty:Get*",
                "config:Describe*",
                "config:Get*",
                "ecr:Describe*",
                "lambda:List*",
                "lambda:Get*",
                "rds:Describe*",
                "eks:List*",
                "eks:Describe*",
                "ssm:Describe*",
                "bedrock:InvokeModel"
            ],
            "Resource": "*"
        }
    ]
}
```

### Streamlit Configuration

Create `.streamlit/config.toml`:

```toml
[server]
headless = true
address = "0.0.0.0"
port = 5000

[browser]
gatherUsageStats = false
```

### Docker Installation

```dockerfile
FROM python:3.11-slim

WORKDIR /app

COPY . .

RUN pip install streamlit boto3 pandas plotly pyyaml requests anthropic reportlab streamlit-autorefresh trafilatura

EXPOSE 5000

CMD ["streamlit", "run", "app.py", "--server.port=5000", "--server.address=0.0.0.0"]
```

Build and run:
```bash
docker build -t aws-security-dashboard .
docker run -p 5000:5000 -e AWS_ACCESS_KEY_ID=your_key -e AWS_SECRET_ACCESS_KEY=your_secret aws-security-dashboard
```

## Troubleshooting

### Common Issues

#### 1. Import Errors
**Error**: `ModuleNotFoundError`
**Solution**: Ensure all dependencies are installed

#### 2. AWS Authentication
**Error**: `NoCredentialsError`
**Solution**: Configure AWS credentials properly

#### 3. Port Already in Use
**Error**: `Port 5000 is already in use`
**Solution**: Use a different port:
```bash
streamlit run app.py --server.port 8501
```

#### 4. Memory Issues
**Error**: Application runs slowly
**Solution**: 
- Increase system memory
- Reduce scan scope
- Monitor fewer regions

### Performance Optimization

#### For Large AWS Environments:
- Select specific regions instead of all regions
- Limit scan results using filters
- Use pagination for large datasets
- Schedule scans during off-peak hours

#### For Better Response Times:
- Enable result caching
- Use faster instance types
- Optimize network connectivity
- Configure appropriate timeouts

### Monitoring and Logging

Enable detailed logging for debugging:

```python
import logging
logging.basicConfig(level=logging.INFO)
```

Check application logs for detailed error messages and performance metrics.