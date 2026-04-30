
from src.AgentModule import AgentClass
from src.AgentTypes.HumanAgent import HumanAgentClass
from src.AgentTypes.TeamAgents import TeamHumanAgentClass
import itertools
import socket
from _thread import *
import errno
import select
from reliableSockets import sendReliablyBinary, recvReliablyBinary2, emptySocket
# Wave 3 CWE-502 remediation: pickle.loads()/dumps() on network-derived bytes
# is replaced with an HMAC-signed JSON envelope. See src/secure_envelope.py
# and SECURITY.md. STIG V-220631 / V-220632, NIST SI-10 / SC-8 / SC-28.
from secure_envelope import EnvelopeError, pack, shared_secret, unpack  # noqa: E402

# Permissive JSON-Schema for agent actions / observed state. The schema enforces
# "must be a JSON object" at the envelope layer; semantic validation is done by
# the game engine against its own invariants. Wave 4 will tighten this.
_AGENT_PAYLOAD_SCHEMA = {"type": "object"}


def nth(iterable, n, default=None):
    "Returns the nth item or a default value"
    return next(itertools.islice(iterable, n, None), default)

class RemoteAgentClass(AgentClass):
    def __init__(self, ID, ClassType, Connection):
        ClassType.__init__(self, ID)
        #self = ClassType(ID)
        self.Connection = Connection

    def updateDecisionModel(self, Observations, PriorActions):
        pass


class RemoteTeamAgentClass(AgentClass):
    def __init__(self, ID, TeamID, ClassType, Connection):
        self.AgentType = ClassType(ID, TeamID)
        self.Connection = Connection
        self.ID = ID
        self.TeamID = TeamID
        self.Actions = {}
        self.Went = 0
        self.Updated = 0

    def getActions(self, ObservedState, State):
        #msg = self.AgentType.printObservedState(ObservedState)
        ActionOptions = {}
        ActionNames = {}
        UnitTypes = {}
        for UnitID, Units in ObservedState.items():
            if len(Units)==1 and nth(Units,0).Owner == self.ID:
                Unit = nth(Units,0)
                ActionOptions[UnitID] = Unit.possibleActions(State)
                UnitTypes[UnitID] = type(Unit)
                UnitActionNames = ()
                for Action in ActionOptions[UnitID][0]:
                    ActionResult = Unit.Actions[Action](State)
                    ActionName = Action
                    if 'advance' in Action:
                        ActionName = 'Advance to '+str(ActionResult[1].Position)
                    if 'turn' in Action:
                        ActionName = 'Change Orientation to '+str(ActionResult[1].Orientation)
                    if 'ram' in Action:
                        ActionName = 'Ram square '+str(ActionResult[1].Position)
                    UnitActionNames += (ActionName,)
                ActionNames.update({UnitID: (UnitActionNames,)})
        return {0: ActionOptions, 1: ObservedState, 2: ActionNames, 3: UnitTypes }

    def requestActions(self, conn, PossibleActions):
        """
        Get the Actions for each unit from the Client `conn`

        Parameters
        ----------
        conn: [socket]
            Client
        PossibleActions: [dict]
            A Dictionary with key `0` containing the available actions for each unit
            and key `1` containing a string of the Clients `ObservedState`
        """
        self.Went = 0
        PossibleActions["contents"] = "requestActions"
        envelope = pack(PossibleActions, shared_secret())
        print('now in RemoteAgent.py, requestActions, line 77  sending PossibleActions   length ', len(envelope))
        sendReliablyBinary(envelope, conn)

        while True:
            try:
                print('now in RemoteAgent.py, requestActions, line 81  receiving AgentAction')
                data = conn.recv(1024)  # this line does not complete until all actions are selected for this player and the data is sent/received
                print('size of data received is: ', len(data))
                if data:
                    try:
                        AgentAction = unpack(data, shared_secret(), _AGENT_PAYLOAD_SCHEMA)
                    except EnvelopeError as envelope_error:
                        print('RemoteAgent.py requestActions: rejecting tampered/invalid envelope:', envelope_error)
                        continue
                    print(AgentAction)
                    break
            except socket.error as error:
                if error.errno == errno.ECONNREFUSED:
                    print(os.strerror(error.errno))
                    board.close()
                    client.close()
                else:
                    print(error)

        self.Went = 1
        self.Actions = AgentAction

    def chooseActions(self, ObservedState, State):
        self.Went = 0
        PossibleActions = self.getActions(ObservedState, State)
        #print(PossibleActions[0])
        #print(self.Connection)
        start_new_thread(self.requestActions, (self.Connection, PossibleActions))
        while self.Went == 0:
            pass
        return self.Actions

    def updateClient(self,NewUnits):
        self.Updated = 0
        d = {}
        for Unit in NewUnits:
            AgentID = Unit.Owner
            newPosition = Unit.Position
            newOrientation = Unit.Orientation
            d[Unit.ID] = {"AgentID":AgentID, "UnitID": Unit.ID, "newPos":newPosition, "newOri":newOrientation}
        d["contents"] = "updateClient"
        print('now in RemoteAgent.py, updateClient, line 118  sending request to updateClient')
        self.Connection.send(pack(d, shared_secret()))
        while True:
            try:
                print('now in RemoteAgent.py, updateClient, line 122  receiving AgentAction')
                data = self.Connection.recv(2048).decode('utf-8')
                print('size of data received is: ', len(data))
                if data:
                    print(data)
                    break
            except Exception as e:
                print('Error', e)
        self.Updated = 1

    def updateDecisionModel(self, Observations, PriorActions):
        pass
