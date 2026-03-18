import json
import pandas as pd
import joblib
from pathlib import Path

# Load the trained model
model_path = Path('nadw-osint-scoring/outputs/model/model.joblib')
model = joblib.load(model_path)

# Load live threats
threats = []
with open('live_threats.jsonl', 'r') as f:
    for line in f:
        if line.strip():
            threats.append(json.loads(line.strip()))

# Remove duplicates
unique_threats = []
seen = set()
for threat in threats:
    threat_key = (threat.get('src_ip'), threat.get('dst_ip'), threat.get('protocol'), threat.get('dst_port'))
    if threat_key not in seen:
        seen.add(threat_key)
        unique_threats.append(threat)

print(f'Scoring {len(unique_threats)} unique live threats...')

# Map live threats to expected NADW format
mapped_threats = []
for i, threat in enumerate(unique_threats):
    # Map to NADW column format
    mapped = {
        'No.': i + 1,
        'Time': 1000 + i,  # Dummy timestamp
        'Source': threat.get('src_ip', '0.0.0.0'),
        'Destination': threat.get('dst_ip', '0.0.0.0'),
        'Length': 64,  # Default length
        'Info': f"{threat.get('src_port', 0)}  >  {threat.get('dst_port', 0)} [{threat.get('protocol', 'TCP')}]"
    }
    mapped_threats.append(mapped)

# Convert to DataFrame
threat_df = pd.DataFrame(mapped_threats)

# Score the threats
try:
    predictions = model.predict_proba(threat_df)
    scores = []

    for i, threat in enumerate(unique_threats):
        threat_id = f'live_threat_{i+1}'
        predicted_class = model.named_steps['clf'].classes_[predictions[i].argmax()]
        scores.append({
            'id': threat_id,
            'features': threat,
            'prediction': str(predicted_class),
            'confidence': float(predictions[i].max()),
            'timestamp': '2026-01-24T12:00:00Z'  # Current timestamp
        })

    # Save live scores
    live_scores_file = Path('nadw-osint-scoring/outputs/scored/live_scores.jsonl')
    live_scores_file.parent.mkdir(parents=True, exist_ok=True)

    with open(live_scores_file, 'w') as f:
        for score in scores:
            f.write(json.dumps(score) + '\n')

    print(f'Successfully scored {len(scores)} live threats')
    for score in scores:
        print(f'  {score["id"]}: {score["prediction"]} ({score["confidence"]:.4f})')

except Exception as e:
    print(f'Error scoring threats: {e}')