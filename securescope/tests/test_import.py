def test_imports():

    assert True

def test_app_import():
    import securescope
    from securescope.cli import main
    assert main.app is not None
