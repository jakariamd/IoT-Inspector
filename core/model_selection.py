import os
import core.common as common

# This file aims to provide a set of functions to 
# perform model selection for a device based on the
# data available in the database.

def import_models():
    # Import all models from the models directory
    # and return them as a list of models

    models_dir = os.path.join(common.get_project_directory(), 'models', 'binary', 'rf')
    model_folders = [name for name in os.listdir(models_dir) if os.path.isdir(os.path.join(models_dir, name))]
    
    return model_folders
