-- DO $$ 
-- DECLARE 
--     r RECORD;
-- BEGIN 
--     FOR r IN (SELECT tablename FROM pg_tables WHERE schemaname = 'public') 
--     LOOP 
--         EXECUTE 'DROP TABLE IF EXISTS ' || quote_ident(r.tablename) || ' CASCADE';
--     END LOOP;
-- END $$;

CREATE TABLE IF NOT EXISTS student(
    stu_id INT PRIMARY KEY,
    firstname VARCHAR(255) NOT NULL,
    lastname VARCHAR(255) NOT NULL,
    email VARCHAR(255) NOT NULL,
    status BOOLEAN DEFAULT false

);

CREATE TABLE IF NOT EXISTS degree (
    degreeID SERIAL PRIMARY KEY,
    degree VARCHAR(100) NOT NULL
);

CREATE TABLE IF NOT EXISTS project (
    projectID SERIAL PRIMARY KEY,
    project_name VARCHAR(200) NOT NULL,
    description TEXT,
    view INT DEFAULT 0,
    expire_after DATE,
    year INT,
    file_path VARCHAR(100)
);



CREATE TABLE IF NOT EXISTS file_Type (
    fileID SERIAL PRIMARY KEY,
    file_type VARCHAR(50) NOT NULL
);

CREATE TABLE IF NOT EXISTS supervisor (
    supervisorID SERIAL PRIMARY KEY,
    name VARCHAR(100) NOT NULL
);

CREATE TABLE IF NOT EXISTS category (
    categoryID SERIAL PRIMARY KEY,
    categoryName VARCHAR(100) NOT NULL
);

CREATE TABLE IF NOT EXISTS project_supervisor (
    projectID INT,
    supervisorID INT,
    PRIMARY KEY (projectID, supervisorID),
    FOREIGN KEY (projectID) REFERENCES project(projectID),
    FOREIGN KEY (supervisorID) REFERENCES supervisor(supervisorID)
);

CREATE TABLE IF NOT EXISTS Project_Category (
    projectID INT,
    categoryID INT,
    PRIMARY KEY (projectID, categoryID),
    FOREIGN KEY (projectID) REFERENCES project(projectID),
    FOREIGN KEY (categoryID) REFERENCES category(categoryID)
);

CREATE TABLE IF NOT EXISTS project_FileType (
    projectID INT,
    fileID INT,
    PRIMARY KEY (projectID, fileID),
    FOREIGN KEY (projectID) REFERENCES project(projectID),
    FOREIGN KEY (fileID) REFERENCES file_Type(fileID)
);

CREATE TABLE IF NOT EXISTS admin (
    id SERIAL PRIMARY KEY,
    role VARCHAR(50),
    email VARCHAR(100)
);

CREATE TABLE IF NOT EXISTS project_student (
    projectID INT,
    stu_id INT,
    FOREIGN KEY (projectID) REFERENCES project(projectID),
    FOREIGN KEY (stu_id) REFERENCES student(stu_id)
);

CREATE TABLE IF NOT EXISTS project_degree (
    projectID INT,
    degreeID INT,
    FOREIGN KEY (projectID) REFERENCES project(projectID),
    FOREIGN KEY (degreeID) REFERENCES degree(degreeID)
);

-- INSERT INTO admin (id, role, email)
-- VALUES (2,
--     'Super_Admin',
--     'kotchakorn_tantr@cmu.ac.th'
--   );

-- INSERT INTO admin (id, role, email)
-- VALUES (1,
--     'Super_Admin',
--     'waraporn_sonwai@cmu.ac.th'
--   );

INSERT INTO admin (id, role, email)
VALUES (1,
    'Super_Admin',
    'teerapat_thu@cmu.ac.th'
  );

-- SELECT * FROM student;

-- DELETE FROM student WHERE stu_id = 65051664;
