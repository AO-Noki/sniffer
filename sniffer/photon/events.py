"""
Processador de eventos do Photon para Albion Online.

Este módulo fornece classes e funções para processar eventos específicos
do jogo Albion Online, incluindo:
- Eventos de jogadores (movimento, combate, chat)
- Eventos de mercado e economia
- Eventos de grupos e guildas
- Extração de metadados e estatísticas
"""

import logging
import json
import time
from typing import Dict, List, Optional, Any, Tuple, Set, Union, Callable
from collections import defaultdict

from .. import config
from .decoder import (
    AlbionOperationCode,
    AlbionEventCode,
    AlbionEventParameters
)

# Configuração do logger
logger = logging.getLogger("sniffer.photon.events")

class EventProcessor:
    """Processador base para eventos do Albion Online."""
    
    def __init__(self):
        """Inicializa o processador de eventos."""
        self.callbacks = []
        self.enabled = True
    
    def add_callback(self, callback: Callable[[Dict[str, Any]], None]) -> None:
        """
        Adiciona uma função de callback para eventos processados.
        
        Args:
            callback: Função que será chamada com o evento processado.
        """
        self.callbacks.append(callback)
    
    def enable(self) -> None:
        """Ativa o processador de eventos."""
        self.enabled = True
    
    def disable(self) -> None:
        """Desativa o processador de eventos."""
        self.enabled = False
    
    def process(self, event_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Processa um evento do Albion Online.
        
        Args:
            event_data: Dados do evento a processar.
            
        Returns:
            Dados processados ou None se o evento não for relevante.
        """
        if not self.enabled:
            return None
        
        # Implementação base - sobrescrever nas subclasses
        return None
    
    def _notify_callbacks(self, processed_data: Dict[str, Any]) -> None:
        """
        Notifica todos os callbacks registrados sobre eventos processados.
        
        Args:
            processed_data: Dados do evento processado.
        """
        for callback in self.callbacks:
            try:
                callback(processed_data)
            except Exception as e:
                logger.error(f"Erro ao chamar callback para evento processado: {e}")

class PlayerEventProcessor(EventProcessor):
    """Processador de eventos relacionados a jogadores."""
    
    def __init__(self):
        """Inicializa o processador de eventos de jogadores."""
        super().__init__()
        self.player_cache = {}  # Cache de informações de jogadores
        self.player_locations = {}  # Últimas localizações conhecidas
        self.player_stats = {}  # Estatísticas de jogadores
    
    def process(self, event_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Processa eventos relacionados a jogadores.
        
        Args:
            event_data: Dados do evento a processar.
            
        Returns:
            Dados processados ou None se o evento não for relevante.
        """
        if not self.enabled:
            return None
            
        event_code = event_data.get("code")
        
        # Processar eventos específicos de jogadores
        if event_code == AlbionEventCode.JOIN:
            return self._process_join(event_data)
        elif event_code == AlbionEventCode.LEAVE:
            return self._process_leave(event_data)
        elif event_code == AlbionEventCode.MOVE:
            return self._process_move(event_data)
        elif event_code == AlbionEventCode.DEATH:
            return self._process_death(event_data)
        elif event_code == AlbionEventCode.CHAT:
            return self._process_chat(event_data)
        
        return None
    
    def _process_join(self, event_data: Dict[str, Any]) -> Dict[str, Any]:
        """Processa evento de entrada de jogador."""
        # Implementação específica
        params = event_data.get("parameters", {})
        player_id = params.get(AlbionEventParameters.PLAYER_ID)
        
        if player_id:
            # Registrar entrada do jogador
            result = {
                "type": "player_join",
                "player_id": player_id,
                "timestamp": time.time()
            }
            
            # Atualizar cache
            if player_id not in self.player_cache:
                self.player_cache[player_id] = {
                    "last_seen": time.time()
                }
            
            self._notify_callbacks(result)
            return result
            
        return {}
    
    def _process_leave(self, event_data: Dict[str, Any]) -> Dict[str, Any]:
        """Processa evento de saída de jogador."""
        # Implementação específica
        params = event_data.get("parameters", {})
        player_id = params.get(AlbionEventParameters.PLAYER_ID)
        
        if player_id:
            # Registrar saída do jogador
            result = {
                "type": "player_leave",
                "player_id": player_id,
                "timestamp": time.time()
            }
            
            # Atualizar cache
            if player_id in self.player_cache:
                self.player_cache[player_id]["last_seen"] = time.time()
            
            # Remover da lista de localizações ativas
            if player_id in self.player_locations:
                self.player_locations.pop(player_id)
            
            self._notify_callbacks(result)
            return result
            
        return {}
    
    def _process_move(self, event_data: Dict[str, Any]) -> Dict[str, Any]:
        """Processa evento de movimento de jogador."""
        # Implementação específica
        params = event_data.get("parameters", {})
        player_id = params.get(AlbionEventParameters.PLAYER_ID)
        pos_x = params.get(AlbionEventParameters.POSITION_X)
        pos_y = params.get(AlbionEventParameters.POSITION_Y)
        
        if player_id and pos_x is not None and pos_y is not None:
            # Registrar movimento do jogador
            result = {
                "type": "player_move",
                "player_id": player_id,
                "position": {"x": pos_x, "y": pos_y},
                "timestamp": time.time()
            }
            
            # Calcular distância da última posição, se disponível
            if player_id in self.player_locations:
                last_pos = self.player_locations[player_id]
                dx = pos_x - last_pos["x"]
                dy = pos_y - last_pos["y"]
                distance = (dx**2 + dy**2)**0.5
                result["distance"] = distance
                result["last_position"] = last_pos
            
            # Atualizar cache de localização
            self.player_locations[player_id] = {"x": pos_x, "y": pos_y}
            
            self._notify_callbacks(result)
            return result
            
        return {}
    
    def _process_death(self, event_data: Dict[str, Any]) -> Dict[str, Any]:
        """Processa evento de morte de jogador."""
        # Implementação específica
        params = event_data.get("parameters", {})
        player_id = params.get(AlbionEventParameters.PLAYER_ID)
        killer_id = params.get(AlbionEventParameters.SOURCE_ID)
        
        if player_id:
            # Registrar morte do jogador
            result = {
                "type": "player_death",
                "player_id": player_id,
                "timestamp": time.time()
            }
            
            if killer_id:
                result["killer_id"] = killer_id
            
            # Atualizar estatísticas
            if player_id not in self.player_stats:
                self.player_stats[player_id] = {"deaths": 0, "kills": 0}
            
            self.player_stats[player_id]["deaths"] += 1
            
            if killer_id and killer_id != player_id:
                if killer_id not in self.player_stats:
                    self.player_stats[killer_id] = {"deaths": 0, "kills": 0}
                
                self.player_stats[killer_id]["kills"] += 1
            
            self._notify_callbacks(result)
            return result
            
        return {}
    
    def _process_chat(self, event_data: Dict[str, Any]) -> Dict[str, Any]:
        """Processa evento de chat."""
        # Implementação específica
        params = event_data.get("parameters", {})
        player_id = params.get(AlbionEventParameters.PLAYER_ID)
        message = params.get(AlbionEventParameters.MESSAGE)
        
        if player_id and message:
            # Registrar mensagem de chat
            result = {
                "type": "player_chat",
                "player_id": player_id,
                "message": message,
                "timestamp": time.time()
            }
            
            self._notify_callbacks(result)
            return result
            
        return {}

class CombatEventProcessor(EventProcessor):
    """Processador de eventos relacionados a combate."""
    
    def __init__(self):
        """Inicializa o processador de eventos de combate."""
        super().__init__()
        self.damage_stats = defaultdict(int)  # Estatísticas de dano por jogador
        self.heal_stats = defaultdict(int)    # Estatísticas de cura por jogador
    
    def process(self, event_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Processa eventos relacionados a combate.
        
        Args:
            event_data: Dados do evento a processar.
            
        Returns:
            Dados processados ou None se o evento não for relevante.
        """
        if not self.enabled:
            return None
            
        event_code = event_data.get("code")
        
        # Processar eventos específicos de combate
        if event_code == AlbionEventCode.COMBAT:
            return self._process_combat(event_data)
        elif event_code == AlbionEventCode.DAMAGE:
            return self._process_damage(event_data)
        elif event_code == AlbionEventCode.HEAL:
            return self._process_heal(event_data)
        
        return None
    
    def _process_combat(self, event_data: Dict[str, Any]) -> Dict[str, Any]:
        """Processa evento de combate."""
        # Implementação específica
        params = event_data.get("parameters", {})
        source_id = params.get(AlbionEventParameters.SOURCE_ID)
        target_id = params.get(AlbionEventParameters.TARGET_ID)
        
        if source_id and target_id:
            # Registrar início de combate
            result = {
                "type": "combat_start",
                "source_id": source_id,
                "target_id": target_id,
                "timestamp": time.time()
            }
            
            self._notify_callbacks(result)
            return result
            
        return {}
    
    def _process_damage(self, event_data: Dict[str, Any]) -> Dict[str, Any]:
        """Processa evento de dano."""
        # Implementação específica
        params = event_data.get("parameters", {})
        source_id = params.get(AlbionEventParameters.SOURCE_ID)
        target_id = params.get(AlbionEventParameters.TARGET_ID)
        value = params.get(AlbionEventParameters.VALUE, 0)
        
        if source_id and target_id and value > 0:
            # Registrar dano causado
            result = {
                "type": "damage",
                "source_id": source_id,
                "target_id": target_id,
                "value": value,
                "timestamp": time.time()
            }
            
            # Atualizar estatísticas
            self.damage_stats[source_id] += value
            result["total_damage"] = self.damage_stats[source_id]
            
            self._notify_callbacks(result)
            return result
            
        return {}
    
    def _process_heal(self, event_data: Dict[str, Any]) -> Dict[str, Any]:
        """Processa evento de cura."""
        # Implementação específica
        params = event_data.get("parameters", {})
        source_id = params.get(AlbionEventParameters.SOURCE_ID)
        target_id = params.get(AlbionEventParameters.TARGET_ID)
        value = params.get(AlbionEventParameters.VALUE, 0)
        
        if source_id and target_id and value > 0:
            # Registrar cura realizada
            result = {
                "type": "heal",
                "source_id": source_id,
                "target_id": target_id,
                "value": value,
                "timestamp": time.time()
            }
            
            # Atualizar estatísticas
            self.heal_stats[source_id] += value
            result["total_heal"] = self.heal_stats[source_id]
            
            self._notify_callbacks(result)
            return result
            
        return {}

class ItemEventProcessor(EventProcessor):
    """Processador de eventos relacionados a itens e inventário."""
    
    def __init__(self):
        """Inicializa o processador de eventos de itens."""
        super().__init__()
        self.item_cache = {}  # Cache de informações de itens
        self.player_inventory = defaultdict(dict)  # Inventário por jogador
    
    def process(self, event_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Processa eventos relacionados a itens.
        
        Args:
            event_data: Dados do evento a processar.
            
        Returns:
            Dados processados ou None se o evento não for relevante.
        """
        if not self.enabled:
            return None
            
        event_code = event_data.get("code")
        
        # Processar eventos específicos de itens
        if event_code == AlbionEventCode.ITEM_DROP:
            return self._process_item_drop(event_data)
        elif event_code == AlbionEventCode.ITEM_PICKUP:
            return self._process_item_pickup(event_data)
        elif event_code == AlbionEventCode.INVENTORY_UPDATE:
            return self._process_inventory_update(event_data)
        elif event_code == AlbionEventCode.LOOT_CHEST:
            return self._process_loot_chest(event_data)
        
        return None
    
    def _process_item_drop(self, event_data: Dict[str, Any]) -> Dict[str, Any]:
        """Processa evento de item descartado."""
        # Implementação específica
        params = event_data.get("parameters", {})
        player_id = params.get(AlbionEventParameters.PLAYER_ID)
        item_id = params.get(AlbionEventParameters.ITEM_ID)
        quantity = params.get(AlbionEventParameters.ITEM_QUANTITY, 1)
        
        if player_id and item_id:
            # Registrar item descartado
            result = {
                "type": "item_drop",
                "player_id": player_id,
                "item_id": item_id,
                "quantity": quantity,
                "timestamp": time.time()
            }
            
            # Atualizar inventário do jogador se estiver sendo rastreado
            if player_id in self.player_inventory and item_id in self.player_inventory[player_id]:
                current_qty = self.player_inventory[player_id].get(item_id, 0)
                new_qty = max(0, current_qty - quantity)
                
                if new_qty > 0:
                    self.player_inventory[player_id][item_id] = new_qty
                else:
                    # Remover item do inventário se quantidade for zero
                    self.player_inventory[player_id].pop(item_id, None)
            
            self._notify_callbacks(result)
            return result
            
        return {}
    
    def _process_item_pickup(self, event_data: Dict[str, Any]) -> Dict[str, Any]:
        """Processa evento de item coletado."""
        # Implementação específica
        params = event_data.get("parameters", {})
        player_id = params.get(AlbionEventParameters.PLAYER_ID)
        item_id = params.get(AlbionEventParameters.ITEM_ID)
        quantity = params.get(AlbionEventParameters.ITEM_QUANTITY, 1)
        
        if player_id and item_id:
            # Registrar item coletado
            result = {
                "type": "item_pickup",
                "player_id": player_id,
                "item_id": item_id,
                "quantity": quantity,
                "timestamp": time.time()
            }
            
            # Atualizar inventário do jogador
            if player_id not in self.player_inventory:
                self.player_inventory[player_id] = {}
                
            current_qty = self.player_inventory[player_id].get(item_id, 0)
            self.player_inventory[player_id][item_id] = current_qty + quantity
            
            self._notify_callbacks(result)
            return result
            
        return {}
    
    def _process_inventory_update(self, event_data: Dict[str, Any]) -> Dict[str, Any]:
        """Processa evento de atualização de inventário."""
        # Implementação específica
        params = event_data.get("parameters", {})
        player_id = params.get(AlbionEventParameters.PLAYER_ID)
        
        if player_id:
            # Registrar atualização de inventário
            result = {
                "type": "inventory_update",
                "player_id": player_id,
                "timestamp": time.time()
            }
            
            # Outros parâmetros específicos de inventário seriam processados aqui
            # quando a estrutura exata dos dados estiver disponível
            
            self._notify_callbacks(result)
            return result
            
        return {}
    
    def _process_loot_chest(self, event_data: Dict[str, Any]) -> Dict[str, Any]:
        """Processa evento de baú de tesouro aberto."""
        # Implementação específica
        params = event_data.get("parameters", {})
        player_id = params.get(AlbionEventParameters.PLAYER_ID)
        
        if player_id:
            # Registrar baú de tesouro aberto
            result = {
                "type": "loot_chest",
                "player_id": player_id,
                "timestamp": time.time()
            }
            
            # Outros parâmetros específicos de loot seriam processados aqui
            # quando a estrutura exata dos dados estiver disponível
            
            self._notify_callbacks(result)
            return result
            
        return {}

# Processador de eventos econômicos (mercado, comércio, etc.)
class EconomyEventProcessor(EventProcessor):
    """Processador de eventos relacionados à economia do jogo."""
    
    def __init__(self):
        """Inicializa o processador de eventos econômicos."""
        super().__init__()
        self.market_data = {}  # Dados de mercado
        self.price_history = defaultdict(list)  # Histórico de preços por item
    
    def process(self, event_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Processa eventos relacionados à economia.
        
        Args:
            event_data: Dados do evento a processar.
            
        Returns:
            Dados processados ou None se o evento não for relevante.
        """
        if not self.enabled:
            return None
            
        event_code = event_data.get("code")
        
        # Processar eventos específicos de economia
        if event_code == AlbionEventCode.GOLD_GAIN:
            return self._process_gold_gain(event_data)
        elif event_code == AlbionEventCode.SILVER_GAIN:
            return self._process_silver_gain(event_data)
        
        # Eventos relacionados ao mercado seriam processados aqui
        # quando identificados
        
        return None
    
    def _process_gold_gain(self, event_data: Dict[str, Any]) -> Dict[str, Any]:
        """Processa evento de ganho de ouro."""
        # Implementação específica
        params = event_data.get("parameters", {})
        player_id = params.get(AlbionEventParameters.PLAYER_ID)
        value = params.get(AlbionEventParameters.GOLD, 0)
        
        if player_id and value > 0:
            # Registrar ganho de ouro
            result = {
                "type": "gold_gain",
                "player_id": player_id,
                "value": value,
                "timestamp": time.time()
            }
            
            self._notify_callbacks(result)
            return result
            
        return {}
    
    def _process_silver_gain(self, event_data: Dict[str, Any]) -> Dict[str, Any]:
        """Processa evento de ganho de prata."""
        # Implementação específica
        params = event_data.get("parameters", {})
        player_id = params.get(AlbionEventParameters.PLAYER_ID)
        value = params.get(AlbionEventParameters.SILVER, 0)
        
        if player_id and value > 0:
            # Registrar ganho de prata
            result = {
                "type": "silver_gain",
                "player_id": player_id,
                "value": value,
                "timestamp": time.time()
            }
            
            self._notify_callbacks(result)
            return result
            
        return {}

# Gerenciador principal de eventos
class EventManager:
    """Gerenciador centralizado de eventos do Albion Online."""
    
    def __init__(self):
        """Inicializa o gerenciador de eventos."""
        self.callbacks = []
        self.enabled = True
        
        # Inicializar processadores específicos
        self.player_processor = PlayerEventProcessor()
        self.combat_processor = CombatEventProcessor()
        self.item_processor = ItemEventProcessor()
        self.economy_processor = EconomyEventProcessor()
        
        # Registrar callbacks dos processadores para o gerenciador principal
        self.player_processor.add_callback(self._handle_processed_event)
        self.combat_processor.add_callback(self._handle_processed_event)
        self.item_processor.add_callback(self._handle_processed_event)
        self.economy_processor.add_callback(self._handle_processed_event)
    
    def add_callback(self, callback: Callable[[Dict[str, Any]], None]) -> None:
        """
        Adiciona uma função de callback para eventos processados.
        
        Args:
            callback: Função que será chamada com o evento processado.
        """
        self.callbacks.append(callback)
    
    def enable(self) -> None:
        """Ativa o gerenciador de eventos e todos os processadores."""
        self.enabled = True
        self.player_processor.enable()
        self.combat_processor.enable()
        self.item_processor.enable()
        self.economy_processor.enable()
    
    def disable(self) -> None:
        """Desativa o gerenciador de eventos e todos os processadores."""
        self.enabled = False
        self.player_processor.disable()
        self.combat_processor.disable()
        self.item_processor.disable()
        self.economy_processor.disable()
    
    def process_event(self, event_data: Dict[str, Any]) -> None:
        """
        Processa um evento do Albion Online, encaminhando-o para os processadores apropriados.
        
        Args:
            event_data: Dados do evento a processar.
        """
        if not self.enabled:
            return
        
        # Delegar o processamento para os processadores específicos
        self.player_processor.process(event_data)
        self.combat_processor.process(event_data)
        self.item_processor.process(event_data)
        self.economy_processor.process(event_data)
    
    def _handle_processed_event(self, processed_data: Dict[str, Any]) -> None:
        """
        Gerencia eventos processados pelos processadores específicos.
        
        Args:
            processed_data: Dados do evento processado.
        """
        # Notificar callbacks sobre o evento processado
        for callback in self.callbacks:
            try:
                callback(processed_data)
            except Exception as e:
                logger.error(f"Erro ao chamar callback para evento: {e}")

# Singleton para uso global
event_manager = EventManager()

def process_albion_event(event_data: Dict[str, Any]) -> None:
    """
    Processa um evento do Albion Online.
    
    Args:
        event_data: Dados do evento a processar.
    """
    event_manager.process_event(event_data)

def add_event_callback(callback: Callable[[Dict[str, Any]], None]) -> None:
    """
    Adiciona um callback para eventos processados.
    
    Args:
        callback: Função que será chamada com o evento processado.
    """
    event_manager.add_callback(callback)

def enable_event_processing() -> None:
    """Ativa o processamento de eventos."""
    event_manager.enable()

def disable_event_processing() -> None:
    """Desativa o processamento de eventos."""
    event_manager.disable()

def enable_player_events() -> None:
    """Ativa apenas o processamento de eventos de jogadores."""
    event_manager.player_processor.enable()

def disable_player_events() -> None:
    """Desativa o processamento de eventos de jogadores."""
    event_manager.player_processor.disable()

def enable_combat_events() -> None:
    """Ativa apenas o processamento de eventos de combate."""
    event_manager.combat_processor.enable()

def disable_combat_events() -> None:
    """Desativa o processamento de eventos de combate."""
    event_manager.combat_processor.disable()

def enable_item_events() -> None:
    """Ativa apenas o processamento de eventos de itens."""
    event_manager.item_processor.enable()

def disable_item_events() -> None:
    """Desativa o processamento de eventos de itens."""
    event_manager.item_processor.disable()

def enable_economy_events() -> None:
    """Ativa apenas o processamento de eventos econômicos."""
    event_manager.economy_processor.enable()

def disable_economy_events() -> None:
    """Desativa o processamento de eventos econômicos."""
    event_manager.economy_processor.disable() 