# Event Validation Tool

A Flask-based web application for validating event logs against predefined rules.

## Features

### 1. Regular Event Validation
Validates event logs in the traditional format with "Event Payload:" key.

**Supported Formats:**
- Single Event format
- Event Payload format  
- Web Event format

### 2. Website Logs Validation (NEW)
Validates website logs in JSON lines format where each line contains a JSON object with `eventname` and `payload` fields.

**Format Example:**
```json
{
    "user_key": "ADGMOT35CHFLVDHBJNIG50K969JBBF7D7BUO2C2MMATUNNAMNCAG",
    "eventname": "add_to_cart",
    "payload": {
        "prid": "13680",
        "prqt": 1,
        "product_name": "9060",
        "category": "Footwear",
        "brand": "New Balance",
        "selling_price": 17999
    }
}
```

### 3. Website Logs V2 Validation (NEW)
Validates website logs in JSON format where each JSON object contains an `event` key for the event name and all other keys as payload (excluding system fields).

**Supported Formats:**
- **Single-line JSON**: Each JSON object on one line
- **Multi-line JSON**: Pretty-printed JSON objects separated by newlines
- **JSON Array**: Array of JSON objects
- **Single JSON Object**: Single JSON object in the file

**Format Examples:**

**Single-line JSON:**
```json
{"src": "GUWAHATI (GAU)", "des": "NEW DELHI (DEL)", "flight_type": "domestic", "event": "flight searched", "url": "https://happyfares.in/?rdt=true~in", "timestamp": 1754392679207}
```

**Multi-line JSON:**
```json
{
    "src": "GUWAHATI (GAU)",
    "des": "NEW DELHI (DEL)",
    "flight_type": "domestic",
    "departure_date": "05-08-2025",
    "passenger_adult": 1,
    "event": "flight searched",
    "url": "https://happyfares.in/?rdt=true~in",
    "purl": "https://happyfares.in/home",
    "title": "Flight Tickets Booking",
    "npv": 1,
    "sts": 455,
    "pts": 322,
    "timestamp": 1754392679207
}
```

**System Fields (excluded from validation):**
- `event` - Event name
- `url` - Current URL
- `purl` - Previous URL
- `title` - Page title
- `npv` - Navigation page view
- `sts` - Session timestamp
- `pts` - Page timestamp
- `timestamp` - Unix timestamp

## Usage

1. **Select Validation Mode:**
   - Choose "Regular Event Validation" for traditional event logs
   - Choose "Website Logs Validation" for JSON lines format with eventname and payload
   - Choose "Website Logs V2 Validation" for JSON lines format with event key and system fields excluded

2. **Upload Files:**
   - CSV File: Contains validation rules (see sample.csv for format)
   - TXT File: Contains event logs

3. **View Results:**
   - Filter by event name, status, expected type, received type
   - Sort by any column
   - Download results as CSV

## CSV Format

Please follow the correct CSV format mentioned in the sample.csv file:

```csv
eventName,eventPayload,dataType,required,condition
event_name,field_name,text/integer/float/date/array,true/false,{}
```

**Note:** All validation is now **case-insensitive**. Event names and field names from both CSV and logs are automatically converted to lowercase for comparison.

## Sample Files

- `sample.csv` - Example validation rules for regular events
- `sample_website_validation.csv` - Example validation rules for website logs
- `sample_website_validation_v2.csv` - Example validation rules for website logs v2
- `samplelog.txt` - Example regular event logs
- `sample_website_logs.txt` - Example website logs in JSON lines format
- `sample_website_logs_v2.txt` - Example website logs v2 in single-line JSON format
- `sample_website_logs_v2_multiline.txt` - Example website logs v2 in multi-line JSON format

## Features

- **Real-time Validation:** Instant validation results
- **Advanced Filtering:** Filter by multiple criteria
- **Line Number Tracking:** For website logs, shows which line each validation error occurred
- **Export Results:** Download validation results as CSV
- **Event Summary:** Overview of events found in logs vs. CSV rules
- **Array Validation:** Support for validating arrays of objects
- **Conditional Validation:** Support for conditional field requirements

## API Endpoints

- `POST /upload` - Regular event validation
- `POST /validate-website-logs` - Website logs validation
- `POST /validate-website-logs-v2` - Website logs v2 validation
- `POST /filter` - Filter validation results
- `POST /download` - Download results as CSV
- `GET /health` - Health check

Feel free to clone and contribute!