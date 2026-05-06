# parser_module/parser.py
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import json
import re
from datetime import datetime

class WindowsLogParser:
    """Парсер Windows Event Logs"""
    
    def __init__(self):
        pass
    
    def parse_event(self, raw_event: str) -> dict:
        """Парсит одно событие Windows Event Log"""
        result = {
            'log_name': '',
            'timestamp': '',
            'level': 'Info',
            'source': '',
            'event_id': '',
            'message': '',
            'is_error': False,
            'is_critical': False,
            'raw': raw_event[:200]  # первые 200 символов для отладки
        }
        
        # Определяем тип лога по содержимому
        if 'Log Name:' in raw_event:
            log_match = re.search(r'Log Name:\s*(\S+)', raw_event)
            if log_match:
                result['log_name'] = log_match.group(1)
        
        # Временная метка
        date_match = re.search(r'Date:\s*([0-9-]+\s+[0-9:]+)', raw_event)
        if date_match:
            result['timestamp'] = date_match.group(1)
        
        # Уровень события (Level)
        level_match = re.search(r'Level:\s*(\w+)', raw_event)
        if level_match:
            level = level_match.group(1)
            if 'Error' in level or 'Ошибк' in level:
                result['level'] = 'Error'
                result['is_error'] = True
            elif 'Warning' in level or 'Предупрежд' in level:
                result['level'] = 'Warning'
        
        # Источник (Source)
        source_match = re.search(r'Source:\s*(\S+)', raw_event)
        if source_match:
            result['source'] = source_match.group(1)
        
        # Event ID
        eid_match = re.search(r'Event ID:\s*(\d+)', raw_event)
        if eid_match:
            result['event_id'] = eid_match.group(1)
        
        # Описание (Description)
        desc_match = re.search(r'Description:\s*(.+?)(?=\n\s*\n|\Z)', raw_event, re.DOTALL)
        if desc_match:
            desc = desc_match.group(1).strip()
            result['message'] = desc[:500]  # ограничиваем длину
        
        # Определяем критичность
        critical_keywords = [
            'fail', 'crash', 'timeout', 'disk full', 'out of memory',
            'отказ', 'сбой', 'критический', 'авария'
        ]
        msg_lower = result['message'].lower()
        if result['is_error'] or any(kw in msg_lower for kw in critical_keywords):
            result['is_critical'] = True
        
        # Специальные критичные Event ID для Security
        critical_ids = ['4624', '4625', '4672', '4673', '4688']
        if result['event_id'] in critical_ids:
            result['is_critical'] = True
            result['level'] = 'Security Alert'
        
        return result

def main():
    """Читает строку из stdin, парсит, выводит JSON"""
    parser = WindowsLogParser()
    
    # Читаем всё содержимое из stdin
    raw_input = sys.stdin.read()
    
    if not raw_input.strip():
        print(json.dumps({"error": "No input"}))
        sys.exit(1)
    
    result = parser.parse_event(raw_input)
    print(json.dumps(result, ensure_ascii=False))

if __name__ == "__main__":
    main()