class BehavioralTwin:
    def __init__(self) -> None:
        self.transitions: dict[str, dict[str, dict[str, int]]] = {}
        self.last_action: dict[str, str] = {}

    def observe(self, actor_id: str, action: str) -> None:
        if actor_id not in self.transitions:
            self.transitions[actor_id] = {}
        
        last = self.last_action.get(actor_id)
        if last:
            if last not in self.transitions[actor_id]:
                self.transitions[actor_id][last] = {}
            self.transitions[actor_id][last][action] = self.transitions[actor_id][last].get(action, 0) + 1
            
        self.last_action[actor_id] = action

    def train(self, actor_id: str, actions: list[str]) -> None:
        for action in actions:
            self.observe(actor_id, action)

    def predict_next(self, actor_id: str, recent_actions: list[str] | None = None) -> dict[str, float]:
        last = recent_actions[-1] if recent_actions else self.last_action.get(actor_id)
        if not last or actor_id not in self.transitions or last not in self.transitions[actor_id]:
            return {}
            
        row = self.transitions[actor_id][last]
        total = sum(row.values())
        if total == 0:
            return {}
            
        return {act: count / total for act, count in row.items()}

    def deviation_score(self, actor_id: str, observed_action: str, recent_actions: list[str] | None = None) -> float:
        probs = self.predict_next(actor_id, recent_actions)
        if not probs:
            return 0.1
            
        prob = probs.get(observed_action, 0.0)
        return round(1.0 - prob, 3)
