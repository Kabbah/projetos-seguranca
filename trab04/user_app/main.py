from user_app import UserApp

def main():
    app = UserApp()

    while True:
        try:
            option = int(input("Menu:\n 1. Obtain ticket\n 2. Access service\n Option: "))
        except ValueError:
            print("Invalid option\n")
            continue

        if option == 1:
            # Pega ID do serviço e duração do ticket por input
            service_id = input("Service ID: ")
            duration = int(input("Duration (minutes): "))
            app.obtain_ticket(service_id, duration)
        elif option == 2:
            # Pega ID do serviço
            service_id = input("Service ID: ")
            if service_id in app.tickets:
                response_str = app.access_service(service_id)
                if response_str is not None:
                    print("Response: " + response_str)
            else:
                print("You haven't acquired a ticket to access " + service_id)

if __name__ == "__main__":
    main()
