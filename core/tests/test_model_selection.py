import unittest
from unittest.mock import patch, MagicMock
import os
import sys

# Add the parent directory to the sys.path to import core module
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

import core.model_selection as model_selection

class TestModelSelection(unittest.TestCase):

    @patch('core.common.get_project_directory')
    @patch('os.listdir')
    @patch('os.path.isdir')
    def test_import_models(self, mock_isdir, mock_listdir, mock_get_project_directory):
        # Setup mock return values
        mock_get_project_directory.return_value = '/fake/project/directory'
        mock_listdir.return_value = ['model1', 'model2', 'not_a_model']
        mock_isdir.side_effect = lambda x: x.endswith('model1') or x.endswith('model2')

        # Call the function
        result = model_selection.import_models()

        # Assertions
        mock_get_project_directory.assert_called_once()
        mock_listdir.assert_called_once_with('/fake/project/directory/models/binary/rf')
        self.assertEqual(result, ['model1', 'model2'])

    @patch('core.common.get_project_directory')
    @patch('os.listdir')
    @patch('os.path.isdir')
    def test_import_models_no_models(self, mock_isdir, mock_listdir, mock_get_project_directory):
        # Setup mock return values
        mock_get_project_directory.return_value = '/fake/project/directory'
        mock_listdir.return_value = []
        mock_isdir.return_value = False

        # Call the function
        result = model_selection.import_models()

        # Assertions
        mock_get_project_directory.assert_called_once()
        mock_listdir.assert_called_once_with('/fake/project/directory/models/binary/rf')
        self.assertEqual(result, [])

if __name__ == '__main__':
    unittest.main()