import pytest
import os
import sys
# Add the parent directory to the sys.path to import core module
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

from core.model_selection import is_close_match, find_best_match

def test_is_close_match():
    assert is_close_match("Hello World", "hello_world", 0.8) == 1
    assert is_close_match("Hello", "H3llo", 0.6) == 1
    assert is_close_match("Python", "Java", 0.5) == 0
    assert is_close_match("GitHub", "GitLab", 0.7) == 0
    assert is_close_match("GitHub", "Git_hub", 0.8) == 1

def test_find_best_match():
    model_names = ["hello_world", "hello", "java", "gitlab"]
    
    assert find_best_match("Hello World", model_names, 0.8) == ("Hello World", "hello_world")
    assert find_best_match("Hello", model_names, 0.6) == ("Hello", "hello")
    assert find_best_match("Python", model_names, 0.5) == ("Python", "unknown model_name")
    assert find_best_match("GitLab", model_names, 0.7) == ("GitLab", "gitlab")
    assert find_best_match("GitHub", model_names, 0.8) == ("GitHub", "unknown model_name")