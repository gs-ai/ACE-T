# ACE-T

ACE-T (Condition Placed Aversion OSINT in Realtime) is a project designed to perform real-time Open Source Intelligence (OSINT) analysis.

## Features

- Real-time data collection
- Data analysis and visualization
- Modular architecture for easy integration of new data sources

## Installation

1. **Clone the repository:**

   ```bash
   git clone https://github.com/gs-ai/ACE-T.git
   cd ACE-T
   ```

2. **Set up the virtual environment:**

   ```bash
   python -m venv ace-t-env
   source ace-t-env/bin/activate  # On Windows: ace-t-env\Scripts\activate
   ```

3. **Install dependencies:**

   ```bash
   pip install -r requirements.txt
   ```

4. **Set up the database:**

   ```bash
   # Ensure you have PostgreSQL installed and running
   createdb ace_t_db
   ```

5. **Apply database migrations:**

   ```bash
   alembic upgrade head
   ```

6. **Run the application:**

   ```bash
   uvicorn backend.app.main:app --reload
   ```

   Access the application at `http://127.0.0.1:8000`.

## Usage

- **API Documentation:**

  Access the interactive API documentation at `http://127.0.0.1:8000/docs`.

- **Creating a User:**

  Send a POST request to `/api/users/` with the following JSON payload:

  ```json
  {
    "name": "John Doe",
    "email": "john.doe@example.com"
  }
  ```

- **Retrieving Users:**

  Send a GET request to `/api/users/` to retrieve a list of users.

## Contributing

1. **Fork the repository.**
2. **Create a new branch:**

   ```bash
   git checkout -b feature-branch-name
   ```

3. **Make your changes and commit them:**

   ```bash
   git commit -m "Description of changes"
   ```

4. **Push to the branch:**

   ```bash
   git push origin feature-branch-name
   ```

5. **Create a pull request.**

## License

This project is licensed under the MIT License. See the `LICENSE` file for details.

## Contact

For any inquiries or issues, please open an issue on the GitHub repository. 
