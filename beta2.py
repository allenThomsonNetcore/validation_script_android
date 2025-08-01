from flask import Flask, request, render_template, jsonify, Response, send_from_directory
from flask_cors import CORS
import csv
import json
import re
import io
import logging
import os
from datetime import datetime
from typing import Dict, List, Tuple

# Configure logging
logging.basicConfig(
    filename='validation_audit.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

app = Flask(__name__, static_folder='static', template_folder='templates')
CORS(app, resources={r"/*": {"origins": "*"}})

# Enable debug mode
app.debug = True

@app.before_request
def log_request_info():
    app.logger.info('Headers: %s', request.headers)
    app.logger.info('Body: %s', request.get_data())
    app.logger.info('URL: %s', request.url)

@app.after_request
def after_request(response):
    app.logger.info('Response: %s', response.get_data())
    return response

@app.errorhandler(404)
def not_found_error(error):
    app.logger.error('Page not found: %s', request.url)
    return jsonify({'error': 'Not found', 'url': request.url}), 404

@app.errorhandler(500)
def internal_error(error):
    app.logger.error('Server Error: %s', error)
    return jsonify({'error': 'Internal server error'}), 500

def log_validation_event(event_type: str, details: Dict):
    """Log validation events for audit purposes"""
    logging.info(f"{event_type}: {json.dumps(details)}")

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

def validate_conditional_fields(payload: Dict, validation: Dict) -> Tuple[bool, str]:
    """Validate fields based on conditional rules"""
    if 'condition' not in validation:
        return True, ""
    
    condition = validation['condition']
    if_field = condition.get('if_field')
    if_value = condition.get('if_value')
    then_field = condition.get('then_field')
    then_type = condition.get('then_type')
    
    if if_field in payload and payload[if_field] == if_value:
        if then_field not in payload:
            return False, f"Required field '{then_field}' is missing when '{if_field}' is '{if_value}'"
        if not validate_value(payload[then_field], then_type):
            return False, f"Field '{then_field}' has invalid type when '{if_field}' is '{if_value}'"
    
    return True, ""

def validate_required_fields(payload: Dict, validations: List[Dict]) -> List[Dict]:
    """Check for required fields and add validation results"""
    results = []
    required_fields = [v['key'] for v in validations if v.get('required', False)]
    
    for field in required_fields:
        if field not in payload:
            results.append({
                'eventName': payload.get('eventName', 'unknown'),
                'key': field,
                'value': None,
                'expectedType': next((v['expectedType'] for v in validations if v['key'] == field), None),
                'receivedType': 'not present',
                'validationStatus': 'Required field missing',
                'comment': 'Required field is missing in the payload'
            })
    
    return results

@app.route('/health')
def health_check():
    return jsonify({"status": "healthy"}), 200

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/static/<path:path>')
def send_static(path):
    return send_from_directory('static', path)

@app.route('/upload', methods=['POST', 'OPTIONS'])
def upload():
    app.logger.info('Upload endpoint called')
    if request.method == 'OPTIONS':
        return '', 200
        
    if 'csv_file' not in request.files or 'txt_file' not in request.files:
        return jsonify({"error": "Both CSV and TXT files are required"}), 400

    try:
        # Log file upload
        log_validation_event('file_upload', {
            'csv_file': request.files['csv_file'].filename,
            'txt_file': request.files['txt_file'].filename,
            'timestamp': datetime.now().isoformat()
        })

        # Parse the CSV file
        csv_file = request.files['csv_file']
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
                
                validation = {
                    'key': row.get('eventPayload', '').strip(),
                    'expectedType': row.get('dataType', '').strip(),
                    'required': row.get('required', '').lower() == 'true',
                    'condition': json.loads(row.get('condition', '{}'))
                }
                event_validations[current_event].append(validation)

        # Parse the TXT file
        txt_file = request.files['txt_file']
        txt_file.stream.seek(0)
        txt_content = txt_file.stream.read().decode('utf-8')
        event_pattern = r"(?:Single Event|Event Payload|Web Event): (\{.*?\})(?=\s*(?:Single Event|Event Payload|Web Event):|$)"

        event_logs = re.findall(event_pattern, txt_content, re.DOTALL)
        parsed_logs = []
        
        for log in event_logs:
            try:
                parsed_log = json.loads(log)
                # Handle Single Event format
                if 'eventName' in parsed_log:
                    # If the log already has eventName, use it directly
                    parsed_log['eventName'] = parsed_log['eventName']
                    parsed_log['payload'] = parsed_log.get('payload', {})
                elif 'event' in parsed_log:
                    # Handle old Single Event format
                    parsed_log['eventName'] = parsed_log['event']
                    parsed_log['payload'] = parsed_log.get('data', {})
                parsed_logs.append(parsed_log)
            except json.JSONDecodeError:
                continue

        # Map event names to payloads
        event_payload_map = {
            log.get("eventName"): log.get("payload", {}) for log in parsed_logs
        }

        # Validate the data
        results = []
        for event_name, validations in event_validations.items():
            payload = event_payload_map.get(event_name, {})
            
            # Check if event name is present in the logs
            if event_name not in event_payload_map:
                # Event name from CSV is not present in the logs
                results.append({
                    'eventName': event_name,
                    'key': 'EVENT_NAME',
                    'value': event_name,
                    'expectedType': 'event',
                    'receivedType': 'not present in logs',
                    'validationStatus': 'Event name not present in the logs',
                    'comment': f'Event "{event_name}" from CSV was not found in the uploaded log file'
                })
                # Skip further validation for this event since it's not in the logs
                continue
            
            # Check required fields first
            required_results = validate_required_fields(payload, validations)
            results.extend(required_results)

            # Check conditional validations
            for validation in validations:
                is_valid, error_msg = validate_conditional_fields(payload, validation)
                if not is_valid:
                    results.append({
                        'eventName': event_name,
                        'key': validation['key'],
                        'value': None,
                        'expectedType': validation['expectedType'],
                        'receivedType': 'invalid',
                        'validationStatus': error_msg
                    })

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

        # Calculate event counts
        csv_events = set(event_validations.keys())
        log_events = set(event_payload_map.keys())
        
        # Add validation entries for extra events (events in logs but not in CSV)
        extra_events = log_events - csv_events
        for extra_event in extra_events:
            payload = event_payload_map.get(extra_event, {})
            results.append({
                'eventName': extra_event,
                'key': 'EVENT_NAME',
                'value': extra_event,
                'expectedType': 'event',
                'receivedType': 'extra event in logs',
                'validationStatus': 'Extra event present in logs',
                'comment': f'Event "{extra_event}" found in logs but not defined in CSV validation rules'
            })
            
            # Also add entries for all fields in the extra event's payload
            if payload:
                for key, value in payload.items():
                    results.append({
                        'eventName': extra_event,
                        'key': key,
                        'value': value,
                        'expectedType': 'EXTRA_EVENT_FIELD',
                        'receivedType': get_value_type(value),
                        'validationStatus': 'Field from extra event',
                        'comment': f'Field from event "{extra_event}" which is not defined in CSV validation rules'
                    })
        
        # Log validation results
        log_validation_event('validation_complete', {
            'total_validations': len(results),
            'valid_count': sum(1 for r in results if r['validationStatus'] == 'Valid'),
            'invalid_count': sum(1 for r in results if r['validationStatus'] != 'Valid'),
            'csv_events_count': len(csv_events),
            'log_events_count': len(log_events),
            'extra_events_count': len(extra_events)
        })

        # Return results with event count information
        response_data = {
            'results': results,
            'summary': {
                'csv_events_count': len(csv_events),
                'log_events_count': len(log_events),
                'csv_events': list(csv_events),
                'log_events': list(log_events),
                'extra_events': list(extra_events)
            }
        }
        
        return jsonify(response_data)

    except Exception as e:
        app.logger.error(f'Error processing files: {str(e)}')
        return jsonify({"error": str(e)}), 500

@app.route('/filter', methods=['POST', 'OPTIONS'])
def filter_results():
    app.logger.info('Filter endpoint called')
    if request.method == 'OPTIONS':
        return '', 200
        
    try:
        data = request.get_json()
        app.logger.info(f'Filter data received: {data}')
        
        results = data.get('results', [])
        filters = data.get('filters', {})
        sort_by = data.get('sort_by')
        sort_order = data.get('sort_order', 'asc')
        date_range = data.get('date_range', {})
        search_term = data.get('search_term', '').lower()
        
        # Apply filters
        filtered_results = results
        if filters:
            for field, values in filters.items():
                if values and isinstance(values, list) and len(values) > 0:
                    if field == 'search_term':
                        filtered_results = [
                            r for r in filtered_results 
                            if any(search_term in str(v).lower() for v in r.values())
                        ]
                    else:
                        filtered_results = [
                            r for r in filtered_results 
                            if str(r.get(field, '')).lower() in [str(v).lower() for v in values]
                        ]
        
        # Apply date range filter
        if date_range:
            start_date = datetime.fromisoformat(date_range.get('start', ''))
            end_date = datetime.fromisoformat(date_range.get('end', ''))
            filtered_results = [
                r for r in filtered_results 
                if r.get('expectedType') == 'date' and 
                start_date <= datetime.fromisoformat(r.get('value', '')) <= end_date
            ]
        
        # Apply sorting
        if sort_by:
            filtered_results.sort(
                key=lambda x: str(x.get(sort_by, '')).lower(),
                reverse=(sort_order == 'desc')
            )
        
        app.logger.info(f'Filtered results count: {len(filtered_results)}')
        return jsonify(filtered_results)
    except Exception as e:
        app.logger.error(f'Error in filter endpoint: {str(e)}')
        return jsonify({'error': str(e)}), 500

@app.route('/download', methods=['POST', 'OPTIONS'])
def download_results():
    app.logger.info('Download endpoint called')
    if request.method == 'OPTIONS':
        return '', 200
        
    try:
        data = request.get_json()
        app.logger.info('Download data received')
        
        results = data.get('results', [])
        
        # Create CSV content
        output = io.StringIO()
        writer = csv.DictWriter(output, fieldnames=['eventName', 'key', 'value', 'expectedType', 'receivedType', 'validationStatus', 'comment'])
        writer.writeheader()
        
        # Add comments to results if not present
        for result in results:
            if 'comment' not in result:
                if result['validationStatus'] == 'Valid':
                    result['comment'] = 'Field validation passed'
                elif result['validationStatus'] == 'Invalid/Wrong datatype/value':
                    result['comment'] = f"Expected type: {result['expectedType']}, Received type: {result['receivedType']}"
                elif result['validationStatus'] == 'Payload value is Empty':
                    result['comment'] = 'Field value is empty or null'
                elif result['validationStatus'] == 'Extra key present in the log':
                    result['comment'] = 'This field was not expected in the validation rules'
                elif result['validationStatus'] == 'Payload not present in the log':
                    result['comment'] = 'Field is missing in the payload'
                elif result['validationStatus'] == 'Event name not present in the logs':
                    result['comment'] = f'Event "{result["eventName"]}" from CSV was not found in the uploaded log file'
                elif result['validationStatus'] == 'Extra event present in logs':
                    result['comment'] = f'Event "{result["eventName"]}" found in logs but not defined in CSV validation rules'
                elif result['validationStatus'] == 'Field from extra event':
                    result['comment'] = f'Field from event "{result["eventName"]}" which is not defined in CSV validation rules'
                else:
                    result['comment'] = result['validationStatus']
        
        writer.writerows(results)
        
        # Create response
        output.seek(0)
        app.logger.info('CSV file generated successfully')
        return Response(
            output,
            mimetype='text/csv',
            headers={
                'Content-Disposition': 'attachment; filename=validation_results.csv',
                'Access-Control-Allow-Origin': '*',
                'Access-Control-Allow-Methods': 'POST, OPTIONS',
                'Access-Control-Allow-Headers': 'Content-Type'
            }
        )
    except Exception as e:
        app.logger.error(f'Error in download endpoint: {str(e)}')
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=10000, debug=True)