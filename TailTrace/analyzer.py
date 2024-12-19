def analyze_packet(packet):
    try:
        # Простий приклад аналізу
        if packet.haslayer("IP"):
            ip_layer = packet["IP"]
            if ip_layer.dst == "127.0.0.1":  # Замість 127.0.0.1 додайте ваші критерії
                return f"Suspicious packet: {ip_layer.src} -> {ip_layer.dst}"
        return None
    except Exception as e:
        return f"Error analyzing packet: {e}"