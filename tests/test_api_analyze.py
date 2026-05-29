def test_health_endpoint(test_client):
    response = test_client.get("/api/v1/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert "model_loaded" in data


def test_analyze_endpoint(test_client, phishing_email):
    response = test_client.post(
        "/api/v1/analyze",
        json={"raw_email": phishing_email, "include_details": False},
    )
    assert response.status_code == 200
    data = response.json()
    assert "verdict" in data
    assert "confidence" in data
    assert "risk_level" in data


def test_analyze_empty_email_rejected(test_client):
    response = test_client.post(
        "/api/v1/analyze",
        json={"raw_email": "   ", "include_details": False},
    )
    assert response.status_code == 422


def test_analyze_missing_field(test_client):
    response = test_client.post("/api/v1/analyze", json={})
    assert response.status_code == 422
