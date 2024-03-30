import os
from keygen import generate_and_save_keys
from discovery import publish, discover, send_message, update_keys
from storage import generate_and_save_key

# Ensure the encryption key is generated on application start
generate_and_save_key()

def init():
    def main_menu():
        action = input('Choose an action (generate-keys, publish, discover, regenerate-keys, exit): ')
        if action == 'generate-keys':
            try:
                generate_and_save_keys()
                print('Keys generated successfully.')
            except Exception as error:
                print(f'Failed to generate keys: {error}')
            main_menu()
        elif action == 'publish':
            try:
                publish()
                print('Publish service started. You can now receive messages.')
            except Exception as error:
                print(f'Failed to publish service: {error}')
            wait_for_command()
        elif action == 'discover':
            try:
                discover()
                print('Discovery started. You can now send messages.')
            except Exception as error:
                print(f'Failed to discover services: {error}')
            wait_for_command()
        elif action == 'regenerate-keys':
            try:
                update_keys()
                print('Key regeneration initiated.')
            except Exception as error:
                print(f'Failed to regenerate keys: {error}')
            main_menu()
        elif action == 'exit':
            print('Exiting application...')
            return
        else:
            print('Invalid option. Please try again.')
            main_menu()

    def wait_for_command():
        command = input('Enter command (send-message <message>, send-file <file-path>, or back): ')
        if command.startswith('send-message'):
            message = command[len('send-message'):].strip()
            send_message(message)
            print('Message sent.')
            wait_for_command()
        elif command.startswith('send-file'):
            file_path = command[len('send-file'):].strip()
            if file_path and os.path.exists(file_path):
                send_message(file_path, True)
                print('File sent.')
            else:
                print('File does not exist or path is incorrect. Please check and try again.')
            wait_for_command()
        elif command == 'back':
            main_menu()
        else:
            print('Unknown command. Please use "send-message <message>", "send-file <file-path>", or "back".')
            wait_for_command()

    main_menu()

init()
