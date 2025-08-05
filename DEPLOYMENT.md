# Deployment Guide for Render

## Issues Fixed

### 1. Port Configuration
- **Problem**: Gunicorn was hardcoded to port 10000, but Render provides its own PORT environment variable
- **Solution**: Updated `gunicorn_config.py` to use `os.environ.get("PORT", 10000)`

### 2. Flask App Port
- **Problem**: Flask app was hardcoded to port 10000
- **Solution**: Updated `beta2.py` to use environment PORT variable

### 3. Health Check
- **Problem**: No health check endpoint for Render
- **Solution**: Added `/health` endpoint and configured in `render.yaml`

## Testing Your Deployment

### 1. Check if the app is running
Visit: `https://your-app-name.onrender.com/health`
Expected response:
```json
{
  "status": "healthy",
  "message": "Validation API is running"
}
```

### 2. Test basic functionality
Visit: `https://your-app-name.onrender.com/test`
Expected response:
```json
{
  "message": "Test endpoint working",
  "endpoints": ["/upload", "/validate-website-logs", "/validate-website-logs-v2", "/filter", "/download"]
}
```

### 3. Check the main page
Visit: `https://your-app-name.onrender.com/`
Should show the validation tool interface.

## Common Issues and Solutions

### 404 Error on Upload
- **Cause**: Frontend is trying to reach wrong URL
- **Solution**: Make sure your frontend is pointing to the correct Render URL

### CORS Issues
- **Cause**: Cross-origin requests blocked
- **Solution**: CORS is already configured in the app with `CORS(app, resources={r"/*": {"origins": "*"}})`

### Port Issues
- **Cause**: App not listening on correct port
- **Solution**: The app now uses Render's PORT environment variable

## Debugging Steps

1. **Check Render Logs**: Go to your Render dashboard and check the logs for any errors
2. **Test Health Endpoint**: Visit `/health` to see if the app is running
3. **Check Network Tab**: In browser dev tools, check if requests are going to the right URL
4. **Verify URL**: Make sure your frontend is using the correct Render URL (not localhost)

## Frontend Configuration

Make sure your frontend JavaScript is pointing to the correct Render URL:

```javascript
// Instead of localhost:10000, use your Render URL
const baseUrl = 'https://your-app-name.onrender.com';

// Update your AJAX calls to use the correct URL
$.ajax({
    url: baseUrl + '/upload',  // or /validate-website-logs, etc.
    // ... rest of your config
});
```

## File Structure for Render

Make sure these files are in your repository:
- `beta2.py` (main Flask app)
- `requirements.txt` (Python dependencies)
- `gunicorn_config.py` (Gunicorn configuration)
- `render.yaml` (Render configuration)
- `templates/index.html` (Frontend template)
- All sample files (optional but helpful) 