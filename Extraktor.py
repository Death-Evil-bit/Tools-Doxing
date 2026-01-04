# extract/table_extractor.py - Table Extraction Module
# Fungsi sudah terintegrasi dalam sql_injector.py
def extract_table_data(injector, url, parameter, table_name):
    """
    Ekstrak data dari tabel tertentu
    Fungsi diimplementasi dalam sql_injector.py.dump_table()
    """
    return injector.dump_table(url, parameter, table_name)
