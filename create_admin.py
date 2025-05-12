from app import app, db, User, Role

def create_admin():
    with app.app_context():
        # Создаем роль администратора
        admin_role = Role(name='Администратор', description='Полный доступ к системе')
        db.session.add(admin_role)
        db.session.commit()

        # Создаем пользователя-администратора
        admin = User(
            login='admin',
            first_name='Администратор',
            role_id=admin_role.id
        )
        admin.set_password('Admin123!')
        
        db.session.add(admin)
        db.session.commit()
        print("Администратор успешно создан!")
        print("Логин: admin")
        print("Пароль: Admin123!")

if __name__ == '__main__':
    create_admin() 