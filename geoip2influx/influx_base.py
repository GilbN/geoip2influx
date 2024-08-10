from abc import ABC, abstractmethod

class InfluxBase(ABC):
    
    @property
    @abstractmethod
    def setup_complete(self) -> bool:
        pass
    
    @setup_complete.setter
    @abstractmethod
    def setup_complete(self, value: bool) -> None:
        pass
    
    @abstractmethod
    def write_to_influx(self, data: str) -> None:
        pass
    
    @abstractmethod
    def setup(self) -> None:
        pass
    
    @abstractmethod
    def test_connection(self) -> None:
        pass
    
    @abstractmethod
    def create_influx_client(self, **kwargs) -> None:
        pass