import os
import json
import pytest
import sys
import os

# Add the parent directory to the sys.path to import core module
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

from core.utils import add_idle_device_in_db

@pytest.fixture
def dummy_json_file(tmp_path):
    # Create a dummy JSON file in the temporary directory
    dummy_data = {
        "devices": {
            "00:1A:2B:3C:4D:5E": {
                "mac_addr": "00:1A:2B:3C:4D:5E",
                "is_idle": 0
            }
        }
    }
    dummy_file_path = tmp_path / "model.json"
    with open(dummy_file_path, 'w') as file:
        json.dump(dummy_data, file, indent=4)
    
    # Yield the file path to the test
    yield dummy_file_path
    
    # Cleanup: Delete the dummy file after the test
    os.remove(dummy_file_path)

def test_add_idle_device_in_db(dummy_json_file, mocker):
    # Mock the get_project_directory function to return the temporary directory
    mock_get_project_directory = mocker.patch('core.utils.get_project_directory')
    mock_get_project_directory.return_value = str(dummy_json_file.parent)

    # Call the function with a known MAC address
    add_idle_device_in_db('00:1A:2B:3C:4D:5E')

    # Verify the content of the file
    with open(dummy_json_file, 'r') as file:
        data = json.load(file)
        assert data['devices']['00:1A:2B:3C:4D:5E']['is_idle'] == 1


def test_add_idle_device_in_db_mac_not_found(dummy_json_file, mocker):
    # Mock the get_project_directory function to return the temporary directory
    mock_get_project_directory = mocker.patch('core.utils.get_project_directory')
    mock_get_project_directory.return_value = str(dummy_json_file.parent)

    # Call the function with a MAC address that does not exist
    add_idle_device_in_db('00:1A:2B:3C:4D:5F')

    # Verify the content of the file
    with open(dummy_json_file, 'r') as file:
        data = json.load(file)
        assert '00:1A:2B:3C:4D:5F' in data['devices']
        assert data['devices']['00:1A:2B:3C:4D:5F']['is_idle'] == 1


def test_set_device_not_idle(dummy_json_file, mocker):
    # Mock the get_project_directory function to return the temporary directory
    mock_get_project_directory = mocker.patch('core.utils.get_project_directory')
    mock_get_project_directory.return_value = str(dummy_json_file.parent)

    # Call the function with a known MAC address and set is_idle to 0
    add_idle_device_in_db('00:1A:2B:3C:4D:5E', is_idle=0)

    # Verify the content of the file
    with open(dummy_json_file, 'r') as file:
        data = json.load(file)
        assert data['devices']['00:1A:2B:3C:4D:5E']['is_idle'] == 0