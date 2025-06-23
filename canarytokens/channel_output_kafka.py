import json

from kafka import KafkaProducer

KAFKA_BROKER_LIST = [
    "localhost:9092",
]
DEFAULT_TOPIC = 'deceptor_test'


def kafka_send(message, topic, broker_list=KAFKA_BROKER_LIST):
    kafka_producer = KafkaProducer(bootstrap_servers=broker_list,
                                   value_serializer=lambda m: json.dumps(m).encode('ascii'))
    kafka_producer.send(topic, message).get(timeout=10)
