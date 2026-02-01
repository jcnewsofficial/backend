# Use a lightweight Python version
FROM python:3.10-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Set work directory
WORKDIR /code

# Install dependencies
COPY requirements.txt /code/
RUN pip install --no-cache-dir -r requirements.txt

# Copy the app folder into the container
COPY ./app /code/app

# Expose the port
EXPOSE 8000

# Command to run the app (referencing the 'app' folder/module)
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
