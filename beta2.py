from flask import Flask, request, render_template, jsonify
import csv
import json
import re

app = Flask(__name__)

def get_value_type(value):
    """Determine the actual type of a value"""
    if value is None:
        return "null"
    elif isinstance(value, bool):
        return "boolean"
    elif isinstance(value, int):
        return "integer"
    elif isinstance(value, float):
        return "float"
    elif isinstance(value, str):
        # Try to determine if it's a date
        try:
            if re.match(r"\d{4}-\d{2}-\d{2}( \d{2}:\d{2}:\d{2})?$", value):
                return "date"
        except:
            pass
        return "text"
    elif isinstance(value, (list, tuple)):
        return "array"
    elif isinstance(value, dict):
        return "object"
    return "unknown"

# Utility functions for validation
def validate_text(value):
    return isinstance(value, str) and value.strip() != ""

def validate_date(value, event_name):
    if event_name == "user_profile_push":
        date_pattern = r"\d{4}-\d{2}-\d{2}"  # YYYY-MM-DD format for user_profile_push
    else:
        date_pattern = r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}"  # YYYY-MM-DD HH:MM:SS for other events
    return isinstance(value, str) and bool(re.fullmatch(date_pattern, value))

def validate_integer(value):
    return isinstance(value, int)

def validate_float(value):
    return isinstance(value, (float))  # Include int for JSON float compatibility

def get_formatted_value(value, expected_type):
    """Format value based on its expected type"""
    if expected_type == "float" and isinstance(value, (float)):
        # Convert to string maintaining decimal places
        str_val = str(value)
        if '.' not in str_val:
            str_val += '.00'
        elif len(str_val.split('.')[1]) == 1:
            str_val += '0'
        return str_val
    return value

def validate_value(value, expected_type, event_name=None):
    if value is None or value == "" or value == "":
        return "Null value"
    if expected_type == "text":
        return validate_text(value)
    elif expected_type == "date":
        return validate_date(value, event_name)
    elif expected_type == "integer":
        return validate_integer(value)
    elif expected_type == "float":
        return validate_float(value)
    return False

def normalize_key(key):
    return key.replace(" ", "_").lower() if key else None

def get_array_field_name(key):
    # Match pattern like "field_name[].subfield" or "items[].field_name"
    match = re.match(r"(.+)\[\]\.(.+)", key)
    if match:
        return match.group(1), match.group(2)
    return None, None

def validate_array_of_objects(array_payload, validations, event_name, results):
    # Extract validation rules for array items
    array_validations = {}
    regular_validations = []
    
    for validation in validations:
        key = validation['key']
        array_field, field_name = get_array_field_name(key)
        
        if array_field and field_name:
            if array_field not in array_validations:
                array_validations[array_field] = {}
            array_validations[array_field][normalize_key(field_name)] = {
                'expectedType': validation['expectedType'],
                'originalKey': key
            }
        else:
            regular_validations.append(validation)

    # If no array validations found, return all validations as regular
    if not array_validations:
        return validations

    # Validate each array field
    for array_field, field_validations in array_validations.items():
        array_data = array_payload.get(array_field, [])
        if not isinstance(array_data, list):
            results.append({
                'eventName': event_name,
                'key': array_field,
                'value': array_data,
                'expectedType': 'array',
                'receivedType': get_value_type(array_data),
                'validationStatus': 'Invalid array field'
            })
            continue

        # Validate each object in the array
        for index, obj in enumerate(array_data):
            if not isinstance(obj, dict):
                results.append({
                    'eventName': event_name,
                    'key': f"{array_field}[{index}]",
                    'value': obj,
                    'expectedType': None,
                    'receivedType': get_value_type(obj),
                    'validationStatus': 'Invalid object in array'
                })
                continue

            # Check for required fields and validate them
            for field_name, validation_info in field_validations.items():
                expected_type = validation_info['expectedType']
                original_key = validation_info['originalKey']
                value = obj.get(field_name)

                validation_result = validate_value(value, expected_type, event_name)
                status = 'Valid' if validation_result and validation_result != "Null value" else \
                        'Payload value is Empty' if validation_result == "Null value" else \
                        'Invalid/Wrong datatype/value'
                
                formatted_value = get_formatted_value(value, expected_type)
                
                results.append({
                    'eventName': event_name,
                    'key': f"{array_field}[{index}].{field_name}",
                    'value': formatted_value,
                    'expectedType': expected_type,
                    'receivedType': get_value_type(value),
                    'validationStatus': status
                })

            # Check for unexpected fields in this object
            for key in obj.keys():
                normalized_key = normalize_key(key)
                if normalized_key not in field_validations:
                    value = obj[key]
                    results.append({
                        'eventName': event_name,
                        'key': f"{array_field}[{index}].{key}",
                        'value': value,
                        'expectedType': None,
                        'receivedType': get_value_type(value),
                        'validationStatus': 'Unexpected key in array object'
                    })

    return regular_validations

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/upload', methods=['POST'])
def upload():
    if 'csv_file' not in request.files or 'txt_file' not in request.files:
        return "Both CSV and TXT files are required", 400

    csv_file = request.files['csv_file']
    txt_file = request.files['txt_file']

    if csv_file.filename == '' or txt_file.filename == '':
        return "Both files must be selected", 400

    try:
        # Parse the CSV file
        csv_file.stream.seek(0)
        csv_reader = csv.DictReader(csv_file.stream.read().decode('utf-8').splitlines())
        
        # Group CSV rows by eventName
        event_validations = {}
        current_event = None
        
        for row in csv_reader:
            event_name = row.get('eventName', '').strip()
            if event_name:
                current_event = event_name
            
            if current_event:
                if current_event not in event_validations:
                    event_validations[current_event] = []
                
                event_validations[current_event].append({
                    'key': row.get('eventPayload', '').strip(),
                    'expectedType': row.get('dataType', '').strip()
                })

        # Parse the TXT file
        txt_file.stream.seek(0)
        txt_content = txt_file.stream.read().decode('utf-8')
        event_pattern = r"(?:Single Event|Event Payload|Web Event): (\{.*?\})(?=\s*(?:Single Event|Event Payload|Web Event):|$)"

        event_logs = re.findall(event_pattern, txt_content, re.DOTALL)
        parsed_logs = [json.loads(log) for log in event_logs]

        # Map event names to payloads
        event_payload_map = {
            log.get("eventName"): log.get("payload", {}) for log in parsed_logs
        }

        # Validate the data
        results = []
        for event_name, validations in event_validations.items():
            payload = event_payload_map.get(event_name, {})

            # Check for array fields in the payload
            array_fields = {k: v for k, v in payload.items() if isinstance(v, list)}
            if array_fields:
                regular_validations = validate_array_of_objects(payload, validations, event_name, results)
                
                # Validate regular fields (non-array fields)
                normalized_payload = {normalize_key(k): v for k, v in payload.items() if k not in array_fields}
                
                # Check for extra keys in regular fields
                extra_keys = set(normalized_payload.keys()) - set([normalize_key(v['key']) for v in regular_validations])
                for extra_key in extra_keys:
                    value = normalized_payload.get(extra_key)
                    results.append({
                        'eventName': event_name,
                        'key': extra_key,
                        'value': value,
                        'expectedType': 'EXTRA',
                        'receivedType': get_value_type(value),
                        'validationStatus': 'Extra key present in the log'
                    })

                # Validate regular fields
                for validation in regular_validations:
                    key = validation['key']
                    expected_type = validation['expectedType']
                    normalized_key = normalize_key(key)
                    value = normalized_payload.get(normalized_key)

                    if not key or not expected_type:
                        results.append({
                            'eventName': event_name,
                            'key': key,
                            'value': None,
                            'expectedType': expected_type,
                            'receivedType': 'unknown',
                            'validationStatus': 'Invalid CSV row'
                        })
                    elif normalized_key not in normalized_payload:
                        results.append({
                            'eventName': event_name,
                            'key': key,
                            'value': None,
                            'expectedType': expected_type,
                            'receivedType': 'not present',
                            'validationStatus': 'Payload not present in the log'
                        })
                    else:
                        validation_result = validate_value(value, expected_type, event_name)
                        status = 'Valid' if validation_result and validation_result != "Null value" else \
                                'Payload value is Empty' if validation_result == "Null value" else \
                                'Invalid/Wrong datatype/value'
                        formatted_value = get_formatted_value(value, expected_type)
                        results.append({
                            'eventName': event_name,
                            'key': key,
                            'value': formatted_value,
                            'expectedType': expected_type,
                            'receivedType': get_value_type(value),
                            'validationStatus': status
                        })
            else:
                # Regular validation for non-array payloads
                normalized_payload = {normalize_key(k): v for k, v in payload.items()}
                extra_keys = set(normalized_payload.keys()) - set([normalize_key(v['key']) for v in validations])
                for extra_key in extra_keys:
                    value = normalized_payload.get(extra_key)
                    results.append({
                        'eventName': event_name,
                        'key': extra_key,
                        'value': value,
                        'expectedType': 'EXTRA',
                        'receivedType': get_value_type(value),
                        'validationStatus': 'Extra key present in the log'
                    })

                for validation in validations:
                    key = validation['key']
                    expected_type = validation['expectedType']

                    if not key or not expected_type:
                        results.append({
                            'eventName': event_name,
                            'key': key,
                            'value': None,
                            'expectedType': expected_type,
                            'receivedType': 'unknown',
                            'validationStatus': 'Invalid CSV row'
                        })
                        continue

                    normalized_key = normalize_key(key)
                    value = normalized_payload.get(normalized_key)

                    if normalized_key not in normalized_payload:
                        results.append({
                            'eventName': event_name,
                            'key': key,
                            'value': None,
                            'expectedType': expected_type,
                            'receivedType': 'not present',
                            'validationStatus': 'Payload not present in the log'
                        })
                    else:
                        validation_result = validate_value(value, expected_type, event_name)
                        status = 'Valid' if validation_result and validation_result != "Null value" else \
                                'Payload value is Empty' if validation_result == "Null value" else \
                                'Invalid/Wrong datatype/value'
                        formatted_value = get_formatted_value(value, expected_type)
                        results.append({
                            'eventName': event_name,
                            'key': key,
                            'value': formatted_value,
                            'expectedType': expected_type,
                            'receivedType': get_value_type(value),
                            'validationStatus': status
                        })

        return jsonify(results)

    except Exception as e:
        return f"Error processing files: {e}", 500

if __name__ == '__main__':
    app.run(debug=True)