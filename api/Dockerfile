FROM python:3.12-alpine

WORKDIR /app

# Create a non-root user and group
RUN addgroup -S appgroup && adduser -S appuser -G appgroup

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Create the uploads directory and set ownership to the new user
RUN mkdir -p /app/uploads && chown -R appuser:appgroup /app/uploads

COPY . .

# Switch to the non-root user
USER appuser

EXPOSE 8000

CMD ["uvicorn", "api:app", "--host", "0.0.0.0", "--port", "8000"]
