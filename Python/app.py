import os
from keygen import keygen
from discovery import discovery

def init():
    kg  = keygen()
    dsc = discovery()

    def main_menu():
        action = input('Choose an action (generate-keys, publish, discover, regenerate-keys, exit): ')
        if action == 'generate-keys':
            try:
                kg.generate_and_save_keys()
                print('Keys generated successfully.')
            except Exception as error:
                print(f'Failed to generate keys: {error}')
            main_menu()

        elif action == 'publish':
            try:
                dsc.publish()
                print('Publish service started. You can now receive messages.')
                wait_for_command()
            except Exception as error:
                print(f'Failed to publish service: {error}')
                main_menu()
            
            
        elif action == 'discover':
            try:
                dsc.discover()
                print('Discovery started. You can now send messages.')
            except Exception as error:
                print(f'Failed to discover services: {error}')
            wait_for_command()

        elif action == 'regenerate-keys':
            try:
                dsc.notify_key_update()
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
            dsc.send_message(message)
            print('Message sent.')
            wait_for_command()

        elif command.startswith('send-file'):
            file_path = command[len('send-file'):].strip()
            if file_path and os.path.exists(file_path):
                dsc.send_message(file_path, True)
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
