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

## Usage

1. **Select Validation Mode:**
   - Choose "Regular Event Validation" for traditional event logs
   - Choose "Website Logs Validation" for JSON lines format

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

## Sample Files

- `sample.csv` - Example validation rules for regular events
- `sample_website_validation.csv` - Example validation rules for website logs
- `samplelog.txt` - Example regular event logs
- `sample_website_logs.txt` - Example website logs in JSON lines format

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
- `POST /filter` - Filter validation results
- `POST /download` - Download results as CSV
- `GET /health` - Health check

Feel free to clone and contribute!