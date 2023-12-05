#method to create  a connection string to postgresql database which is in neon free tier
def create_connection_string():
    username = 'younganesh278'
    password = 'E3q6viRIGdjl'
    host = 'ep-restless-queen-96402308.us-east-2.aws.neon.tech'
    database = 'PatientHeartRate'
    return f'postgresql+psycopg2://{username}:{password}@{host}/{database}?sslmode=require'