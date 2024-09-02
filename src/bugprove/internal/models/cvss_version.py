# coding: utf-8

"""
BugProve Public API

No description provided (generated by Openapi Generator https://github.com/openapitools/openapi-generator)

The version of the OpenAPI document: 20240716
Generated by OpenAPI Generator (https://openapi-generator.tech)

Do not edit the class manually.
"""  # noqa: E501

from __future__ import annotations
import json
from enum import Enum
from typing_extensions import Self


class CvssVersion(str, Enum):
    """
    CvssVersion
    """

    """
    allowed enum values
    """
    UNKNOWN = "Unknown"
    V2 = "V2"
    V3 = "V3"
    V31 = "V31"
    V4 = "V4"

    @classmethod
    def from_json(cls, json_str: str) -> Self:
        """Create an instance of CvssVersion from a JSON string"""
        return cls(json.loads(json_str))
