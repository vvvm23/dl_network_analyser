from keras.models import load_model
from time import sleep
# Print Start Banner
def banner():
    f = open("./banner.txt")
    lines = f.readlines()
    print(''.join(lines))
    f.close()
    pass

# Update and display UI
def display_ui():
    pass

# Hook into CICFlowMeter program and get output
def hook():
    pass

def run_sentinel():
    # Setup code
    print("INFO:\t\t XYZ SENTINEL START.")
    # Infinite Loop
    while True:
        print("WARNING:\t\tNo flow data received")
        sleep(0.5)
    pass

if __name__ == '__main__':
    banner()
    run_sentinel()
    pass