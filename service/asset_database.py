from repository.asset_database import AssetDatabase


class assets:
    def __init__(self):
        pass

    @staticmethod
    def get_database():
        db = AssetDatabase()
        return db
