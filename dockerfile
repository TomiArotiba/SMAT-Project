#Use an official Python runtime as a parent image
FROM python:3.10-slim

#Set the working directory in the container
WORKDIR /app

#Copy all files into the container
COPY . /app

#Install system dependencies required for WeasyPrint
RUN apt-get update && apt-get install -y \
    libpango-1.0-0 \
    libgdk-pixbuf2.0-0 \
    libffi-dev \
    libpangocairo-1.0-0 \
    libcairo2 \
    libjpeg62-turbo \
    libgdk-pixbuf2.0-dev \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

#Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

#Run risk_model.py to generate the training model
RUN python risk_model.py

#Set Flask environment variables
ENV FLASK_APP=app.run
ENV FLASK_ENV=development

#Expose port 5000 for Flask
EXPOSE 5000

#Command to run the Flask app
CMD ["flask", "run", "--host=0.0.0.0"]
