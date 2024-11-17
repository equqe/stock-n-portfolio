# consumers.py

from channels.generic.websocket import AsyncWebsocketConsumer
from channels.layers import get_channel_layer
from asgiref.sync import async_to_sync
import json

class NotificationConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        self.room_name = "notifications"
        self.room_group_name = "notifications_group"

        await self.channel_layer.group_add(
            self.room_group_name,
            self.channel_name
        )

        await self.accept()

    async def disconnect(self, close_code):
        await self.channel_layer.group_discard(
            self.room_group_name,
            self.channel_name
        )

    async def receive(self, text_data):
        pass

    async def send_notification(self, event):
        message = event['message']

        await self.send(text_data=json.dumps({
            'message': message
        }))
