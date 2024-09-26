# Use an official Python runtime as the base image
FROM python:3.11

# Set the working directory in the container
WORKDIR /app

# Copy the requirements file into the container
COPY requirements.txt .

# Install the required packages
RUN pip install --no-cache-dir -r requirements.txt

# Copy the app directory into the container
COPY . .

# Set environment variables
ENV FLASK_RUN_HOST=0.0.0.0
ENV FLASK_APP=wsgi.py
ENV FLASK_ENV=production

# Expose the port the app runs on
EXPOSE 5000

# Run the command to start the Flask app
CMD ["sh", "-c", "python -c 'from login_app import db, create_app; app=create_app(); app.app_context().push(); db.create_all()' && gunicorn -b 0.0.0.0:5000 'wsgi:login_app'"]

