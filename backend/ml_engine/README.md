# ML Engine

This folder contains scripts used for training and detecting anomalies on network
and PLC sensor data.  Before running any Python code you must activate the
workspace virtual environment and install dependencies:

```powershell
cd ml_engine
python -m venv venv          # (only once)
venv\Scripts\activate        # on Windows
python -m pip install -r requirements.txt
```

In VS Code ensure the Python interpreter is set to `ml_engine/venv` so that
import errors from `pandas`, `numpy`, `scikit-learn` and `joblib` disappear.

Once dependencies are installed execute the training script:

```powershell
python train.py
```

The script will create a `models/` directory and save trained models and
scalers used by `detect.py` (currently empty placeholder).
