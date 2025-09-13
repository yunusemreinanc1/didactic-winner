import datetime
import pytz

def main():
    # Get current UTC time
    utc_now = datetime.datetime.now(pytz.UTC)
    print(f"Bot running at: {utc_now.strftime('%Y-%m-%d %H:%M:%S')} UTC")
    
    # Add your bot logic here
    
if __name__ == "__main__":
    main()