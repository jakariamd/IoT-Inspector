import functools
import libinspector


def get_hostnames(mac_address):
    db_conn, rwlock = libinspector.global_state.db_conn_and_lock
    with rwlock:
        # Get src_hostnames where mac_address = dest_mac_address
        # UNION
        # Get dest_hostnames where mac_address = src_mac_address
        query = """
        SELECT DISTINCT hostname FROM (
            SELECT src_hostname as hostname 
            FROM network_flows 
            WHERE dest_mac_address = ? AND src_hostname IS NOT NULL AND src_hostname != ''
            
            UNION
            
            SELECT dest_hostname as hostname 
            FROM network_flows 
            WHERE src_mac_address = ? AND dest_hostname IS NOT NULL AND dest_hostname != ''
        )
        """
        
        result = db_conn.execute(query, (mac_address, mac_address))
        rows = result.fetchall()
        
        # Extract hostnames from rows and return as list
        hostnames = [row[0] for row in rows if row[0]]
        # print(f"Hostnames for MAC {mac_address}: {hostnames}")
        return hostnames if hostnames else None

