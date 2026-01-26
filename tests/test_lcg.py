import pytest

def generate_lcg(client, count=10):
    return client.post("/lcg/random", json={"count": count})

def test_lcg_period(client):
    res = client.get("/lcg/period")
    assert res.status_code == 200

    period = res.json()
    assert isinstance(period, int)
    assert period > 0

    res2 = generate_lcg(client, count=period + 1)
    assert res2.status_code == 200

    new_period = client.get("/lcg/period").json()
    assert new_period == period


def test_lcg_random_sequence(client):
    count = 5
    res = generate_lcg(client, count=count)

    assert res.status_code == 200

    seq = res.json().get("sequence")

    assert isinstance(seq, list)
    assert len(seq) == count
    assert all(isinstance(num, int) for num in seq)


def test_lcg_test_generator(client):
    res = client.post("/lcg/test_generator", params={"n": 100})

    assert res.status_code == 200

    data = res.json()

    assert "LCG" in data
    assert "random" in data
    assert "true_pi" in data

    assert "pi_estimate" in data["LCG"]
    assert "P" in data["LCG"]
    assert "pi_estimate" in data["random"]
    assert "P" in data["random"]

    assert isinstance(data["LCG"]["pi_estimate"], float)
    assert isinstance(data["random"]["pi_estimate"], float)
    assert data["true_pi"] > 3.0
