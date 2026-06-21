from abc import ABC, abstractmethod

class BaseModelAdapter(ABC):
    """
    Abstract base class for all model adapters.
    Adapters wrap the communication logic with different LLM endpoints.
    """
    
    @abstractmethod
    def query(self, prompt: str, system_prompt: str = None) -> str:
        """
        Sends a query (prompt) to the model along with an optional system prompt,
        returning the response text.
        """
        pass
