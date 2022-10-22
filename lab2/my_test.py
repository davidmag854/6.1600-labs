import argparse
import importlib
import json
import ag.common.testing as testing

importlib.import_module('ag.ag2.runner')
results = testing.run_tests()