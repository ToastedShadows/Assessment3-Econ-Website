import os
import sqlite3

def format_size(size_in_bytes):
    if size_in_bytes is None:
        return "Not Found"
    if size_in_bytes == 0:
        return "0 Bytes"
    if size_in_bytes < 1024:
        return f"{size_in_bytes} Bytes"
    elif size_in_bytes < 1024**2:
        return f"{size_in_bytes / 1024:.2f} KB"
    elif size_in_bytes < 1024**3:
        return f"{size_in_bytes / 1024**2:.2f} MB"
    else:
        return f"{size_in_bytes / 1024**3:.2f} GB"

def get_product_attribute_sizes():
    try:
        conn = sqlite3.connect('database.db')
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        
        c.execute('SELECT * FROM products')
        products = c.fetchall()
        
        if not products:
            print("No products found in the database.")
            return

        column_names = products[0].keys()
        totals = {col: 0 for col in column_names}
        
    finally:
        if 'conn' in locals() and conn:
            conn.close()
    
    print("Product Attribute Sizes:")
    print("========================")
    
    for product in products:
        print(f"\n--- Product: {product['name']} (ID: {product['id']}) ---")
        for col_name in column_names:
            value = product[col_name]
            size_in_bytes = None
            
            if col_name == 'image' and value:
                full_path = os.path.join('static', 'uploads', value)
                if os.path.exists(full_path):
                    size_in_bytes = os.path.getsize(full_path)
            elif value is not None:
                size_in_bytes = len(str(value).encode('utf-8'))
            else:
                size_in_bytes = 0
            
            if size_in_bytes is not None:
                totals[col_name] += size_in_bytes

            display_size = format_size(size_in_bytes)
            raw_bytes_str = f"{size_in_bytes} Bytes" if size_in_bytes is not None else "Not Found"
            
            print(f"- {col_name:<15}: {raw_bytes_str:<20} | For Display: {display_size}")

    print("\n\n--- Totals for All Products ---")
    print("=============================")
    for col_name, total_bytes in totals.items():
        display_size = format_size(total_bytes)
        raw_bytes_str = f"{total_bytes} Bytes"
        print(f"- {col_name:<15}: {raw_bytes_str:<20} | For Display: {display_size}")

if __name__ == '__main__':
    get_product_attribute_sizes() 