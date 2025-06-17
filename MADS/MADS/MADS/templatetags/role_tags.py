from django import template
from django.conf import settings

register = template.Library()

@register.filter
def lookup(dictionary, key):
    return dictionary.get(key, [])