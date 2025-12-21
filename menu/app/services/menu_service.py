import pandas as pd
import os

def get_menu_by_restaurant_id(restaurant_id):
    file_path = f"data/{restaurant_id}.csv"

    if not os.path.exists(file_path):
        return {"error": f"餐廳 {restaurant_id} 的菜單不存在"}

    df = pd.read_csv(file_path, encoding="utf-8-sig")  # 加 BOM 處理

    required_columns = ["dish_id", "dish_name", "price", "category_name", "is_available_status"]
    missing = [col for col in required_columns if col not in df.columns]
    if missing:
        return {"error": f"CSV 缺少欄位：{', '.join(missing)}"}

    categories = {}
    for _, row in df.iterrows():
        cat = row["category_name"]
        if cat not in categories:
            categories[cat] = []
        categories[cat].append({
            "dish_id": row["dish_id"],
            "name": row["dish_name"],
            "price": row["price"],
            "is_available": str(row["is_available_status"]).upper() == "TRUE"
        })

    menu_categories = [
        {
            "category_id": f"CAT{idx+1:03}",
            "name": cat,
            "dishes": dishes
        }
        for idx, (cat, dishes) in enumerate(categories.items())
    ]

    return {
        "restaurant_id": restaurant_id,
        "menu_categories": menu_categories
    }