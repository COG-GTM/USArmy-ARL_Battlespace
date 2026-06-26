print(f'Invoking __init__.py for {__name__}')

import src.AgentTypes, src.Games, src.StateTypes, src.UnitTypes

# The UI package requires Tk (tkinter), which is unavailable in headless
# environments (e.g. the simulation harness and CI). It is only needed for the
# visualized server, so import it optionally to keep the package importable.
try:
    import src.UI_Files
except ImportError:
    pass

import src.AgentModule, src.GameModule, src.StateModule, src.UnitModule, src.CSVOutputModule
                     
                     