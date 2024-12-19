from scapy.all import sniff

def start_sniffing(target, verbose=False):
    # Фільтр для захоплення трафіку
    filter_str = f"host {target}"
    if verbose:
        print(f"[INFO] Applying filter: {filter_str}")

    # Використання генератора для повернення пакетів
    return sniff(filter=filter_str, prn=lambda x: x, store=False)